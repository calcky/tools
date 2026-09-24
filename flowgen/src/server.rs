use crate::{
    buffers::BufferPool,
    datagram::{RecvBatch, SendBatch, BATCH_SIZE},
    net,
    options::Config,
    record::{Event, Kind, Mode, Recording},
    tuning,
    wire::{self, Header},
};
use mio::{Events, Interest, Poll, Token, Waker};
use socket2::Socket;
use std::{
    cell::Cell,
    collections::{BTreeSet, HashMap, HashSet, VecDeque},
    io::{self, Write},
    net::{SocketAddr, UdpSocket},
    os::fd::AsRawFd,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc, Arc, Mutex, OnceLock,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

#[path = "ready.rs"]
mod ready;
use crate::slots::SlotTable;
use ready::ReadyQueue;

const LISTENER: Token = Token(0);
const UDP: Token = Token(1);
const WAKE: Token = Token(usize::MAX);
const MAX_RUNS: usize = 16;
const MAX_PENDING: usize = 1024;
const MAX_PEERS: usize = 1_048_576;
const RETIRE_BATCH: usize = 1024;
const MAX_RETIREMENTS: usize = 131072;
const CONTROL_MAX: usize = wire::HEADER + 8 * RETIRE_BATCH;
const PEER_BYTES: usize = 256 * 1024;
const WORKER_BYTES: usize = 64 * 1024 * 1024;
const QUANTUM: usize = 64;
const TCP_BATCH: usize = 16;
const TICK: Duration = Duration::from_millis(25);
const PUBLISH: Duration = Duration::from_millis(100);
const REQUESTS: usize = 0;
const RESPONSES: usize = 1;
const REQUEST_BYTES: usize = 2;
const RESPONSE_BYTES: usize = 3;
const ACTIVE: usize = 4;
const FAILED: usize = 5;
const LIMITED: usize = 6;
const INVALID: usize = 7;

#[derive(Default)]
struct Counts([AtomicU64; 8]);

#[repr(align(128))]
#[derive(Default)]
struct Traffic([AtomicU64; 4]);

#[derive(Default)]
struct LocalTraffic([Cell<u64>; 4]);

impl LocalTraffic {
    fn add(&self, index: usize, value: u64) {
        self.0[index].set(self.0[index].get() + value);
    }

    fn publish(&self, snapshot: &Traffic) {
        for (value, counter) in self.0.iter().zip(&snapshot.0) {
            counter.store(value.get(), Ordering::Relaxed);
        }
    }
}

fn traffic_snapshot(counts: &Counts, traffic: &[Traffic]) -> [u64; 8] {
    let mut values = counts.snapshot();
    for shard in traffic {
        for (value, counter) in values.iter_mut().zip(&shard.0) {
            *value += counter.load(Ordering::Relaxed);
        }
    }
    values
}

impl Counts {
    fn add(&self, n: usize, value: u64) {
        self.0[n].fetch_add(value, Ordering::Relaxed);
    }

    fn snapshot(&self) -> [u64; 8] {
        std::array::from_fn(|n| self.0[n].load(Ordering::Relaxed))
    }
}

// Recent retired IDs are exact. Once this bounded window fills, its lower
// watermark rejects older OPENs conservatively, including very delayed setups.
// DATA never admits a flow. No history proportional to total churn is retained.
struct Flows {
    live: HashMap<u64, FlowOwner>,
    retired: BTreeSet<u64>,
    floor: Option<u64>,
    history: usize,
}

struct FlowOwner {
    worker: usize,
    retiring: bool,
}

impl Flows {
    fn new(target: usize) -> Self {
        Self {
            live: HashMap::new(),
            retired: BTreeSet::new(),
            floor: None,
            history: target.saturating_mul(2).clamp(1024, 131072),
        }
    }

    fn admissible(&self, flow: u64) -> bool {
        !self.live.contains_key(&flow)
            && !self.retired.contains(&flow)
            && self.floor.is_none_or(|floor| flow > floor)
    }

    fn retire(&mut self, flow: u64) -> bool {
        let existed = self.live.remove(&flow).is_some();
        if self.floor.is_none_or(|floor| flow > floor) {
            self.retired.insert(flow);
        }
        if self.retired.len() > self.history {
            self.floor = self.retired.pop_first();
        }
        existed
    }
}

struct Run {
    id: u64,
    tcp: bool,
    length: usize,
    timeout: Duration,
    start: Instant,
    expires: Option<Instant>,
    alive: AtomicBool,
    counts: Counts,
    traffic: Vec<Traffic>,
    flows: Mutex<Flows>,
    retiring: AtomicUsize,
}

impl Run {
    fn snapshot(&self) -> [u64; 8] {
        traffic_snapshot(&self.counts, &self.traffic)
    }
    fn active(&self) -> bool {
        self.alive.load(Ordering::Acquire)
            && self.expires.is_none_or(|expires| Instant::now() < expires)
    }

    fn matches(&self, h: Header) -> bool {
        self.active() && h.run == self.id && h.tcp == self.tcp
    }
}

type Retirements = Mutex<VecDeque<(Arc<Run>, u64)>>;

struct Shared {
    runs: Mutex<HashMap<u64, Arc<Run>>>,
    controls: AtomicUsize,
    pending: AtomicUsize,
    active: AtomicUsize,
    queued_retirements: AtomicUsize,
    counts: Counts,
    traffic: Vec<Traffic>,
    retirements: Vec<Retirements>,
    wake: Vec<OnceLock<Arc<Waker>>>,
}

fn reserve(counter: &AtomicUsize, cap: usize) -> bool {
    counter
        .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |n| {
            (n < cap).then_some(n + 1)
        })
        .is_ok()
}

impl Shared {
    fn new(workers: usize) -> Self {
        Self {
            runs: Mutex::new(HashMap::new()),
            controls: AtomicUsize::new(0),
            pending: AtomicUsize::new(0),
            active: AtomicUsize::new(0),
            queued_retirements: AtomicUsize::new(0),
            counts: Counts::default(),
            traffic: (0..workers).map(|_| Traffic::default()).collect(),
            retirements: (0..workers).map(|_| Mutex::new(VecDeque::new())).collect(),
            wake: (0..workers).map(|_| OnceLock::new()).collect(),
        }
    }

    fn count(&self, run: &Run, index: usize, value: u64) {
        run.counts.add(index, value);
        self.counts.add(index, value);
    }

    fn snapshot(&self) -> [u64; 8] {
        traffic_snapshot(&self.counts, &self.traffic)
    }

    fn accept(&self, h: Header) -> Result<Arc<Run>, Kind> {
        let target = usize::try_from(h.flow).map_err(|_| Kind::Invalid)?;
        if h.kind != wire::CONTROL
            || h.len != wire::HEADER
            || h.run == 0
            || target == 0
            || h.seq == 0
            || !(wire::HEADER..=wire::MAX).contains(&(h.aux as usize))
        {
            return Err(Kind::Invalid);
        }
        let start = Instant::now();
        let expires = if h.stamp == wire::UNLIMITED_RUN {
            None
        } else {
            Some(
                start
                    .checked_add(Duration::from_nanos(h.stamp))
                    .ok_or(Kind::Invalid)?,
            )
        };
        let mut runs = self.runs.lock().unwrap();
        if runs.contains_key(&h.run) {
            return Err(Kind::Invalid);
        }
        if runs.len() >= MAX_RUNS || !reserve(&self.controls, MAX_RUNS) {
            return Err(Kind::Limited);
        }
        // Failed controls can leave queued cleanup behind. Keep headroom for
        // one outstanding batch from every still-admitted control.
        if self.queued_retirements.load(Ordering::Acquire)
            >= MAX_RETIREMENTS - MAX_RUNS * RETIRE_BATCH
        {
            self.controls.fetch_sub(1, Ordering::AcqRel);
            return Err(Kind::Limited);
        }
        let run = Arc::new(Run {
            id: h.run,
            tcp: h.tcp,
            length: h.aux as usize,
            timeout: Duration::from_nanos(h.seq),
            start,
            expires,
            alive: AtomicBool::new(true),
            counts: Counts::default(),
            traffic: (0..self.traffic.len())
                .map(|_| Traffic::default())
                .collect(),
            flows: Mutex::new(Flows::new(target)),
            retiring: AtomicUsize::new(0),
        });
        runs.insert(h.run, run.clone());
        Ok(run)
    }

    fn lookup(&self, id: u64) -> Option<Arc<Run>> {
        self.runs
            .lock()
            .unwrap()
            .get(&id)
            .filter(|r| r.active())
            .cloned()
    }

    fn end(&self, run: &Arc<Run>) {
        let _flows = run.flows.lock().unwrap();
        run.alive.store(false, Ordering::Release);
        let mut runs = self.runs.lock().unwrap();
        if runs.get(&run.id).is_some_and(|r| Arc::ptr_eq(r, run)) {
            runs.remove(&run.id);
        }
        drop(runs);
        drop(_flows);
        self.wake_workers();
    }

    fn wake_workers(&self) {
        for wake in &self.wake {
            if let Some(wake) = wake.get() {
                let _ = wake.wake();
            }
        }
    }

    fn expire(&self) {
        self.runs.lock().unwrap().retain(|_, run| {
            if !run.active() {
                run.alive.store(false, Ordering::Release);
                false
            } else {
                true
            }
        });
    }

    fn admit(&self, run: &Run, flow: u64, worker: usize) -> Result<(), Kind> {
        let mut flows = run.flows.lock().unwrap();
        if !run.active() || !flows.admissible(flow) {
            return Err(Kind::Invalid);
        }
        // A replacement OPEN may arrive before another worker handles the old
        // flow's close. The client's target is not a server admission limit.
        flows.live.insert(
            flow,
            FlowOwner {
                worker,
                retiring: false,
            },
        );
        self.active.fetch_add(1, Ordering::Relaxed);
        self.count(run, ACTIVE, 1);
        Ok(())
    }

    fn release(&self, run: &Run, flow: u64) {
        if run.flows.lock().unwrap().retire(flow) {
            self.active.fetch_sub(1, Ordering::AcqRel);
            let previous = run.counts.0[ACTIVE].fetch_sub(1, Ordering::Release);
            self.counts.0[ACTIVE].fetch_sub(1, Ordering::Relaxed);
            if previous == 1 && !run.alive.load(Ordering::Acquire) {
                self.wake_workers();
            }
        }
    }

    fn retire_batch(&self, run: &Arc<Run>, payload: &[u8]) -> Result<(), Kind> {
        if run.tcp
            || payload.is_empty()
            || payload.len() > RETIRE_BATCH * 8
            || !payload.len().is_multiple_of(8)
        {
            return Err(Kind::Invalid);
        }
        let mut flows = run.flows.lock().unwrap();
        for id in payload.as_chunks::<8>().0 {
            let flow = u64::from_be_bytes(*id);
            let Some(owner) = flows.live.get_mut(&flow) else {
                // Reliable CLOSE can overtake a delayed UDP OPEN.
                flows.retire(flow);
                continue;
            };
            if owner.retiring {
                continue;
            }
            let mut queue = self.retirements[owner.worker].lock().unwrap();
            // Also bound stale queued entries globally when a direct UDP CLOSE
            // wins the race. This bounds control work, not live sessions.
            if !reserve(&self.queued_retirements, MAX_RETIREMENTS) {
                return Err(Kind::Limited);
            }
            run.retiring.fetch_add(1, Ordering::Relaxed);
            queue.push_back((run.clone(), flow));
            owner.retiring = true;
        }
        drop(flows);
        self.wake_workers();
        Ok(())
    }
}

#[derive(Default)]
struct Budget {
    used: usize,
}

impl Budget {
    fn take(&mut self, n: usize) -> bool {
        if n > WORKER_BYTES.saturating_sub(self.used) {
            return false;
        }
        self.used += n;
        true
    }

    fn give(&mut self, n: usize) {
        debug_assert!(n <= self.used);
        self.used -= n;
    }
}

// Return one frame per step, reserving its full allocation before copying its
// body. Read-ahead is bounded inline storage, including for unauthenticated peers.
const INPUT_BATCH_BYTES: usize = 2048;

struct Input {
    prefix: [u8; 8],
    prefix_len: usize,
    frame: Vec<u8>,
    filled: usize,
    since: Option<Instant>,
    batch: [u8; INPUT_BATCH_BYTES],
    batch_start: usize,
    batch_end: usize,
    batch_since: Option<Instant>,
}

impl Default for Input {
    fn default() -> Self {
        Self {
            prefix: [0; 8],
            prefix_len: 0,
            frame: Vec::new(),
            filled: 0,
            since: None,
            batch: [0; INPUT_BATCH_BYTES],
            batch_start: 0,
            batch_end: 0,
            batch_since: None,
        }
    }
}

enum ReadStep {
    Progress,
    Frame(Vec<u8>),
    Blocked,
    Eof,
}

impl Input {
    fn resume_after_pause(&mut self, since: Instant, now: Instant) {
        let paused = now.saturating_duration_since(since);
        for at in [&mut self.since, &mut self.batch_since]
            .into_iter()
            .flatten()
        {
            *at += paused;
        }
    }

    fn read(
        &mut self,
        socket: &Socket,
        budget: &mut Budget,
        buffers: &mut BufferPool,
        queued: usize,
        max_frame: usize,
    ) -> Result<ReadStep, Kind> {
        self.read_with(budget, buffers, queued, max_frame, |output| {
            net::recv(socket, output)
        })
    }

    fn read_with(
        &mut self,
        budget: &mut Budget,
        buffers: &mut BufferPool,
        queued: usize,
        max_frame: usize,
        recv: impl FnOnce(&mut [u8]) -> io::Result<usize>,
    ) -> Result<ReadStep, Kind> {
        if self.batch_start == self.batch_end {
            // Large bodies keep the direct receive path instead of requiring
            // one syscall and a copy for every read-ahead-sized chunk.
            let direct = self.frame.len().saturating_sub(self.filled) > INPUT_BATCH_BYTES;
            let output = if direct {
                &mut self.frame[self.filled..]
            } else {
                &mut self.batch[..]
            };
            let n = match recv(output) {
                Ok(0) => {
                    return if self.since.is_some() {
                        Err(Kind::Failed)
                    } else {
                        Ok(ReadStep::Eof)
                    }
                }
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(ReadStep::Blocked),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => return Ok(ReadStep::Progress),
                Err(_) => return Err(Kind::Failed),
            };
            let now = Instant::now();
            self.since.get_or_insert(now);
            if direct {
                self.filled += n;
            } else {
                self.batch_start = 0;
                self.batch_end = n;
                self.batch_since = Some(now);
            }
        }
        if self.frame.is_empty() {
            let n = (8 - self.prefix_len).min(self.batch_end - self.batch_start);
            self.prefix[self.prefix_len..self.prefix_len + n]
                .copy_from_slice(&self.batch[self.batch_start..self.batch_start + n]);
            self.batch_start += n;
            self.prefix_len += n;
            if self.prefix_len < 8 {
                return Ok(ReadStep::Progress);
            }
            let len = u32::from_be_bytes(self.prefix[4..8].try_into().unwrap()) as usize;
            if &self.prefix[..4] != b"FLWG" || !(wire::HEADER..=max_frame).contains(&len) {
                return Err(Kind::Invalid);
            }
            if len > PEER_BYTES.saturating_sub(queued) || !budget.take(len) {
                return Err(Kind::Limited);
            }
            self.frame = buffers.take(len);
            self.frame[..8].copy_from_slice(&self.prefix);
            self.filled = 8;
        }
        let n = (self.frame.len() - self.filled).min(self.batch_end - self.batch_start);
        self.frame[self.filled..self.filled + n]
            .copy_from_slice(&self.batch[self.batch_start..self.batch_start + n]);
        self.batch_start += n;
        self.filled += n;
        if self.filled == self.frame.len() {
            self.prefix_len = 0;
            self.filled = 0;
            self.since = if self.batch_start < self.batch_end {
                self.batch_since
            } else {
                None
            };
            Ok(ReadStep::Frame(std::mem::take(&mut self.frame)))
        } else {
            Ok(ReadStep::Progress)
        }
    }
}

struct Output {
    bytes: Vec<u8>,
    offset: usize,
    h: Header,
    run: Option<Arc<Run>>,
    since: Instant,
}

impl Output {
    fn new(bytes: Vec<u8>, h: Header, run: Option<Arc<Run>>) -> Self {
        Self {
            bytes,
            offset: 0,
            h,
            run,
            since: Instant::now(),
        }
    }
}

enum Role {
    Pending,
    Control {
        run: Arc<Run>,
        last_seq: Option<u64>,
        ended: bool,
    },
    Data {
        run: Arc<Run>,
        flow: u64,
    },
}

impl Role {
    fn run(&self) -> Option<&Arc<Run>> {
        match self {
            Self::Pending => None,
            Self::Control { run, .. } | Self::Data { run, .. } => Some(run),
        }
    }
}

struct Peer {
    socket: Socket,
    role: Role,
    input: Input,
    output: VecDeque<Output>,
    queued: usize,
    accepted: Instant,
    deadline: Option<Instant>,
    readable: bool,
    writable: bool,
    write_interest: bool,
    scheduled: bool,
    closing: bool,
    final_report: Option<(Header, Instant)>,
    teardown_deadline: Option<Instant>,
}

impl Peer {
    fn report_ready(&self) -> bool {
        self.final_report.is_some_and(|(header, _)| {
            let run = self.role.run().unwrap();
            if header.kind == wire::END {
                run.counts.0[ACTIVE].load(Ordering::Acquire) == 0
            } else {
                run.retiring.load(Ordering::Acquire) == 0
            }
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
struct Key {
    addr: SocketAddr,
    run: u64,
    flow: u64,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct UdpReady {
    ticket: u64,
    key: Key,
}

struct UdpPeer {
    run: Arc<Run>,
    output: VecDeque<Output>,
    queued: usize,
    ticket: Option<u64>,
}

struct LocalRun {
    run: Arc<Run>,
    traffic: LocalTraffic,
    recorder: Recording,
    tcp: HashSet<Token>,
    udp: HashMap<u64, Key>,
}

impl LocalRun {
    fn record(&mut self, o: &Config, h: Header, kind: Kind) {
        if o.recording != "off" {
            self.recorder.push(Event {
                flow: h.flow,
                seq: h.seq,
                time_ns: if o.recording == "events" {
                    net::ns(self.run.start)
                } else {
                    0
                },
                value: 0,
                len: h.len as u32,
                kind,
            });
        }
    }
}

struct Worker<'a> {
    o: &'a Config,
    id: usize,
    shared: Arc<Shared>,
    stop: Arc<AtomicBool>,
    poll: Poll,
    listener: Socket,
    udp: UdpSocket,
    peers: SlotTable<Peer>,
    datagrams: HashMap<Key, UdpPeer>,
    local: HashMap<u64, LocalRun>,
    traffic: LocalTraffic,
    deadlines: BTreeSet<(Instant, Token)>,
    ready: ReadyQueue<Token>,
    udp_ready: ReadyQueue<UdpReady>,
    udp_ticket: u64,
    udp_write_interest: bool,
    udp_writable: bool,
    budget: Budget,
    buffers: BufferPool,
    ending: HashSet<Token>,
    finalize: Option<mpsc::SyncSender<Recording>>,
    finalizer: Option<JoinHandle<io::Result<()>>>,
}

fn listener(o: &Config, tcp: bool) -> io::Result<Socket> {
    let socket = net::socket(o.ipv6, tcp)?;
    tuning::apply_socket(&socket, o)?;
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    socket.bind(&net::any(o.ipv6, o.port).into())?;
    if tcp {
        socket.listen(o.backlog)?;
    }
    Ok(socket)
}

impl<'a> Worker<'a> {
    fn new(
        o: &'a Config,
        id: usize,
        shared: Arc<Shared>,
        stop: Arc<AtomicBool>,
    ) -> io::Result<Self> {
        let poll = Poll::new()?;
        let listener = listener(o, true)?;
        let udp: UdpSocket = listener_udp(o)?;
        net::register(&poll, listener.as_raw_fd(), LISTENER, Interest::READABLE)?;
        net::register(&poll, udp.as_raw_fd(), UDP, Interest::READABLE)?;
        shared.wake[id]
            .set(Arc::new(Waker::new(poll.registry(), WAKE)?))
            .map_err(|_| io::Error::other("duplicate server worker ID"))?;
        let (finalize, finalizer) = if o.recording != "events" {
            (None, None)
        } else {
            let (sender, receiver) = mpsc::sync_channel::<Recording>(MAX_RUNS);
            let stopped = stop.clone();
            let finalizer = thread::Builder::new()
                .name(format!("flowgen-finalize-{id}"))
                .spawn(move || {
                    let mut result = Ok(());
                    for recorder in receiver {
                        match recorder.finish() {
                            Ok(summary) if summary.dropped > 0 => {
                                eprintln!(
                                    "server worker={id} recording_dropped={}",
                                    summary.dropped
                                );
                            }
                            Ok(_) => {}
                            Err(e) => {
                                eprintln!("server worker={id} recording error: {e}");
                                stopped.store(true, Ordering::Release);
                                if result.is_ok() {
                                    result = Err(e);
                                }
                            }
                        }
                    }
                    result
                })?;
            (Some(sender), Some(finalizer))
        };
        Ok(Self {
            o,
            id,
            shared,
            stop,
            poll,
            listener,
            udp,
            peers: SlotTable::with_capacity(MAX_PEERS),
            datagrams: HashMap::new(),
            local: HashMap::new(),
            traffic: LocalTraffic::default(),
            deadlines: BTreeSet::new(),
            ready: ReadyQueue::with_capacity(1_048_576),
            udp_ready: ReadyQueue::with_capacity(WORKER_BYTES / wire::HEADER),
            udp_ticket: 0,
            udp_write_interest: false,
            udp_writable: true,
            budget: Budget::default(),
            buffers: BufferPool::default(),
            ending: HashSet::new(),
            finalize,
            finalizer,
        })
    }

    fn local_run(&mut self, run: &Arc<Run>) -> io::Result<bool> {
        if let Some(local) = self.local.get(&run.id) {
            return Ok(Arc::ptr_eq(&local.run, run));
        }
        if self.local.len() >= MAX_RUNS {
            return Ok(false);
        }
        let mode = Mode::parse(&self.o.recording).unwrap_or(Mode::Events);
        let suffix = match mode {
            Mode::Events | Mode::Off => "fgr",
            Mode::Summary => "summary.csv",
        };
        let path = self
            .o
            .output
            .join(format!("server-{}-{}.{}", run.id, self.id, suffix));
        let recorder = Recording::create(&path, run.id, run.tcp, true, mode)?;
        self.local.insert(
            run.id,
            LocalRun {
                run: run.clone(),
                traffic: LocalTraffic::default(),
                recorder,
                tcp: HashSet::new(),
                udp: HashMap::new(),
            },
        );
        Ok(true)
    }

    fn record(&mut self, run: &Run, h: Header, kind: Kind) {
        if self.o.recording == "off" {
            return;
        }
        if let Some(local) = self.local.get_mut(&run.id) {
            local.record(self.o, h, kind);
        }
    }

    fn outcome(&mut self, run: Option<&Arc<Run>>, h: Header, kind: Kind) {
        let index = match kind {
            Kind::Failed => Some(FAILED),
            Kind::Invalid => Some(INVALID),
            Kind::Limited => Some(LIMITED),
            _ => None,
        };
        if let Some(run) = run {
            if let Some(index) = index {
                let flows = run.flows.lock().unwrap();
                if !run.alive.load(Ordering::Acquire) && flows.live.is_empty() {
                    // Errors arriving after the run's final cutoff remain
                    // visible globally but cannot mutate an ended run's report.
                    self.shared.counts.add(index, 1);
                    return;
                }
                self.shared.count(run, index, 1);
                self.record(run, h, kind);
                return;
            }
            self.record(run, h, kind);
        } else if let Some(index) = index {
            self.shared.counts.add(index, 1);
        }
    }

    fn request(&mut self, h: Header) {
        self.data_event(h, Kind::ServerRequest);
    }

    fn data_event(&mut self, h: Header, kind: Kind) {
        let (count, bytes) = match kind {
            Kind::ServerRequest => (REQUESTS, REQUEST_BYTES),
            Kind::ServerResponse => (RESPONSES, RESPONSE_BYTES),
            _ => unreachable!(),
        };
        let local = self.local.get_mut(&h.run).unwrap();
        local.traffic.add(count, 1);
        local.traffic.add(bytes, h.len as u64);
        self.traffic.add(count, 1);
        self.traffic.add(bytes, h.len as u64);
        local.record(self.o, h, kind);
    }

    fn publish_run(&self, run: &Run) {
        if let Some(local) = self
            .local
            .get(&run.id)
            .filter(|local| std::ptr::eq(local.run.as_ref(), run))
        {
            local.traffic.publish(&run.traffic[self.id]);
        }
        self.traffic.publish(&self.shared.traffic[self.id]);
    }

    fn publish_traffic(&self) {
        for local in self.local.values() {
            local.traffic.publish(&local.run.traffic[self.id]);
        }
        self.traffic.publish(&self.shared.traffic[self.id]);
    }

    fn sent(&mut self, output: &Output) {
        if let Some(run) = &output.run {
            if output.h.kind == wire::DATA {
                self.data_event(output.h, Kind::ServerResponse);
            } else if output.h.kind == wire::ACK {
                self.record(run, output.h, Kind::Ready);
            }
        }
    }

    fn accept_connections(&mut self) -> io::Result<bool> {
        for _ in 0..QUANTUM {
            let (socket, _) = match self.listener.accept() {
                Ok(pair) => pair,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(false),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == io::ErrorKind::ConnectionAborted => continue,
                Err(e) => return Err(e),
            };
            if !reserve(&self.shared.pending, MAX_PENDING) {
                self.shared.counts.add(LIMITED, 1);
                continue;
            }
            let setup = socket
                .set_nonblocking(true)
                .and_then(|_| socket.set_tcp_nodelay(true));
            let accepted = Instant::now();
            let deadline = accepted + self.o.timeout;
            let Some(token) = self.peers.insert(Peer {
                socket,
                role: Role::Pending,
                input: Input::default(),
                output: VecDeque::new(),
                queued: 0,
                accepted,
                deadline: Some(deadline),
                readable: true,
                writable: true,
                write_interest: false,
                scheduled: true,
                closing: false,
                final_report: None,
                teardown_deadline: None,
            }) else {
                self.shared.pending.fetch_sub(1, Ordering::AcqRel);
                self.shared.counts.add(LIMITED, 1);
                continue;
            };
            if let Err(e) = setup.and_then(|_| {
                net::register(
                    &self.poll,
                    self.peers.get(token).unwrap().socket.as_raw_fd(),
                    token,
                    Interest::READABLE,
                )
            }) {
                self.peers.remove(token);
                self.shared.pending.fetch_sub(1, Ordering::AcqRel);
                return Err(e);
            }
            self.deadlines.insert((deadline, token));
            let _ = self.ready.push_back(token);
        }
        Ok(true)
    }

    fn authenticate(
        &mut self,
        token: Token,
        peer: &mut Peer,
        h: Header,
    ) -> io::Result<Result<(), Kind>> {
        let result = match h.kind {
            wire::CONTROL => match self.shared.accept(h) {
                Ok(run) => {
                    self.shared.pending.fetch_sub(1, Ordering::AcqRel);
                    peer.role = Role::Control {
                        run: run.clone(),
                        last_seq: None,
                        ended: false,
                    };
                    if !self.local_run(&run)? {
                        return Ok(Err(Kind::Limited));
                    }
                    Ok(())
                }
                Err(kind) => Err(kind),
            },
            wire::OPEN if valid_open(h) && h.tcp => {
                match self.shared.lookup(h.run) {
                    Some(run) if run.matches(h) && run.length == h.aux as usize => {
                        if !self.local_run(&run)? {
                            return Ok(Err(Kind::Limited));
                        }
                        match self.shared.admit(&run, h.flow, self.id) {
                            Ok(()) => {
                                self.shared.pending.fetch_sub(1, Ordering::AcqRel);
                                self.local.get_mut(&run.id).unwrap().tcp.insert(token);
                                self.record(&run, h, Kind::Open);
                                peer.role = Role::Data { run, flow: h.flow };
                                Ok(())
                            }
                            Err(kind) => {
                                self.outcome(Some(&run), h, kind);
                                // The unauthenticated socket has no run to charge on close.
                                Err(Kind::Closed)
                            }
                        }
                    }
                    _ => Err(Kind::Invalid),
                }
            }
            _ => Err(Kind::Invalid),
        };
        Ok(result)
    }

    fn frame(
        &mut self,
        token: Token,
        peer: &mut Peer,
        mut bytes: Vec<u8>,
    ) -> io::Result<Result<(), Kind>> {
        let h = match wire::parse(&bytes) {
            Ok(h) => h,
            Err(_) => {
                self.budget.give(bytes.len());
                return Ok(Err(Kind::Invalid));
            }
        };
        if matches!(peer.role, Role::Pending) {
            let auth = self.authenticate(token, peer, h);
            match auth {
                Ok(Ok(())) => {}
                Ok(Err(kind)) => {
                    self.budget.give(bytes.len());
                    return Ok(Err(kind));
                }
                Err(e) => {
                    self.budget.give(bytes.len());
                    return Err(e);
                }
            }
            let mut reply = h;
            reply.kind = if h.kind == wire::CONTROL {
                wire::ACCEPT
            } else {
                wire::ACK
            };
            bytes[8] = reply.kind;
            let run = if h.kind == wire::OPEN {
                peer.role.run().cloned()
            } else {
                None
            };
            peer.queued += bytes.len();
            peer.output.push_back(Output::new(bytes, reply, run));
            return Ok(Ok(()));
        }
        match &mut peer.role {
            Role::Data { run, flow } => {
                if !run.matches(h) || h.flow != *flow {
                    self.budget.give(bytes.len());
                    return Ok(Err(Kind::Invalid));
                }
                if h.kind == wire::CLOSE && h.len == wire::HEADER {
                    self.budget.give(bytes.len());
                    peer.closing = true;
                } else if h.kind == wire::DATA && h.len == run.length {
                    self.request(h);
                    peer.queued += bytes.len();
                    peer.output
                        .push_back(Output::new(bytes, h, Some(run.clone())));
                } else {
                    self.budget.give(bytes.len());
                    return Ok(Err(Kind::Invalid));
                }
            }
            Role::Control {
                run,
                last_seq,
                ended,
            } => {
                self.budget.give(bytes.len());
                let retirement = h.kind == wire::CLOSE
                    && !run.tcp
                    && h.flow == 0
                    && h.len > wire::HEADER
                    && h.len <= CONTROL_MAX
                    && (h.len - wire::HEADER).is_multiple_of(8);
                let report = matches!(h.kind, wire::STATS | wire::END) && h.len == wire::HEADER;
                if !run.matches(h)
                    || *ended
                    || !(retirement || report)
                    || last_seq.is_some_and(|seq| h.seq <= seq)
                {
                    return Ok(Err(Kind::Invalid));
                }
                if retirement {
                    if let Err(kind) = self.shared.retire_batch(run, &bytes[wire::HEADER..]) {
                        return Ok(Err(kind));
                    }
                }
                *last_seq = Some(h.seq);
                self.buffers.give(bytes);
                if h.kind == wire::END || retirement {
                    if h.kind == wire::END {
                        *ended = true;
                        peer.teardown_deadline =
                            Some(Instant::now() + run.timeout.max(wire::TEARDOWN_TIMEOUT));
                        self.shared.end(run);
                    }
                    // Do not acknowledge another retirement batch until its
                    // owners drain it. At most one batch per control is queued.
                    peer.final_report = Some((h, Instant::now()));
                    self.ending.insert(token);
                    return Ok(Ok(()));
                }
                if wire::REPORT_LEN > PEER_BYTES.saturating_sub(peer.queued)
                    || !self.budget.take(wire::REPORT_LEN)
                {
                    return Ok(Err(Kind::Limited));
                }
                let reply = Header {
                    kind: wire::STATS,
                    len: wire::REPORT_LEN,
                    ..h
                };
                let mut bytes = self.buffers.take(reply.len);
                reply.encode_into(&mut bytes);
                for (n, value) in run.snapshot().iter().enumerate() {
                    bytes[wire::HEADER + n * 8..wire::HEADER + (n + 1) * 8]
                        .copy_from_slice(&value.to_be_bytes());
                }
                peer.queued += bytes.len();
                peer.output.push_back(Output::new(bytes, reply, None));
            }
            Role::Pending => unreachable!(),
        }
        Ok(Ok(()))
    }

    fn flush_tcp(&mut self, peer: &mut Peer) -> Result<bool, Kind> {
        if peer.output.is_empty() {
            return Ok(false);
        }
        for _ in 0..QUANTUM {
            let sent_bytes = {
                let mut slices = [std::io::IoSlice::new(&[]); TCP_BATCH];
                let mut count = 0;
                for output in peer.output.iter().take(TCP_BATCH) {
                    let bytes = &output.bytes[output.offset..];
                    if bytes.is_empty() {
                        break;
                    }
                    slices[count] = std::io::IoSlice::new(bytes);
                    count += 1;
                }
                if count == 1 {
                    net::send(&peer.socket, slices[0].as_ref())
                } else {
                    net::send_vectored(&peer.socket, &slices[..count])
                }
            };
            match sent_bytes {
                Ok(0) => return Err(Kind::Failed),
                Ok(n) => {
                    let mut remaining = n;
                    while remaining > 0 {
                        let front = peer.output.front_mut().unwrap();
                        let available = front.bytes.len() - front.offset;
                        let consumed = available.min(remaining);
                        front.offset += consumed;
                        remaining -= consumed;
                        if front.offset == front.bytes.len() {
                            let sent = peer.output.pop_front().unwrap();
                            peer.queued -= sent.bytes.len();
                            self.budget.give(sent.bytes.len());
                            self.sent(&sent);
                            self.buffers.give(sent.bytes);
                        }
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    peer.writable = false;
                    return Ok(false);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(Kind::Failed),
            }
            if peer.output.is_empty() {
                break;
            }
        }
        Ok(!peer.output.is_empty())
    }

    fn service_tcp(&mut self, token: Token, peer: &mut Peer) -> io::Result<Result<bool, Kind>> {
        if let Some(run) = peer.role.run() {
            if !run.active() && !matches!(peer.role, Role::Control { ended: true, .. }) {
                return Ok(Err(Kind::Closed));
            }
        }
        let mut more = false;
        if peer.writable {
            match self.flush_tcp(peer) {
                Ok(again) => more |= again,
                Err(kind) => return Ok(Err(kind)),
            }
        }
        if peer.readable && !peer.closing && peer.final_report.is_none() {
            for n in 0..QUANTUM {
                let max_frame = match &peer.role {
                    Role::Data { run, .. } => run.length,
                    Role::Control { .. } => CONTROL_MAX,
                    _ => wire::HEADER,
                };
                match peer.input.read(
                    &peer.socket,
                    &mut self.budget,
                    &mut self.buffers,
                    peer.queued,
                    max_frame,
                ) {
                    Ok(ReadStep::Frame(frame)) => {
                        if let Err(kind) = self.frame(token, peer, frame)? {
                            return Ok(Err(kind));
                        }
                        if peer.closing || peer.final_report.is_some() {
                            break;
                        }
                    }
                    Ok(ReadStep::Progress) => {}
                    Ok(ReadStep::Blocked) => {
                        peer.readable = false;
                        break;
                    }
                    Ok(ReadStep::Eof) => {
                        if let Role::Control { run, .. } = &peer.role {
                            self.shared.end(run);
                        }
                        peer.closing = true;
                        break;
                    }
                    Err(kind) => return Ok(Err(kind)),
                }
                if n == QUANTUM - 1 {
                    more = true;
                }
            }
        }
        if let Some((h, since)) = peer.final_report {
            let run = peer.role.run().unwrap();
            // END freezes admissions. Each data owner publishes traffic before
            // releasing ACTIVE, so acquiring zero makes the final report exact.
            if peer.report_ready() {
                if wire::REPORT_LEN > PEER_BYTES.saturating_sub(peer.queued)
                    || !self.budget.take(wire::REPORT_LEN)
                {
                    return Ok(Err(Kind::Limited));
                }
                let reply = Header {
                    kind: wire::STATS,
                    len: wire::REPORT_LEN,
                    ..h
                };
                let mut bytes = self.buffers.take(reply.len);
                reply.encode_into(&mut bytes);
                for (n, value) in run.snapshot().iter().enumerate() {
                    bytes[wire::HEADER + n * 8..wire::HEADER + (n + 1) * 8]
                        .copy_from_slice(&value.to_be_bytes());
                }
                peer.queued += bytes.len();
                peer.output.push_back(Output::new(bytes, reply, None));
                peer.final_report = None;
                peer.closing = h.kind == wire::END;
                peer.input.resume_after_pause(since, Instant::now());
                more |= !peer.closing && peer.readable;
                self.ending.remove(&token);
            }
        }
        // A new response gets an immediate send attempt. Only WouldBlock arms
        // WRITABLE; an empty queue always removes that interest.
        if peer.writable {
            match self.flush_tcp(peer) {
                Ok(again) => more |= again,
                Err(kind) => return Ok(Err(kind)),
            }
        }
        if peer.closing && peer.output.is_empty() {
            return Ok(Err(Kind::Closed));
        }
        let write_interest = !peer.output.is_empty() && !peer.writable;
        if write_interest != peer.write_interest {
            let interest = if write_interest {
                Interest::READABLE | Interest::WRITABLE
            } else {
                Interest::READABLE
            };
            net::update(&self.poll, peer.socket.as_raw_fd(), token, interest)?;
            peer.write_interest = write_interest;
        }
        Ok(Ok(more))
    }

    fn deadline(&mut self, token: Token, peer: &mut Peer) {
        if let Some(old) = peer.deadline.take() {
            self.deadlines.remove(&(old, token));
        }
        if let Some(at) = peer.teardown_deadline {
            self.deadlines.insert((at, token));
            peer.deadline = Some(at);
            return;
        }
        let timeout = peer.role.run().map_or(self.o.timeout, |run| run.timeout);
        let mut deadline = match &peer.role {
            Role::Pending => Some(peer.accepted + self.o.timeout),
            Role::Control {
                run, ended: false, ..
            } => run.expires,
            _ => None,
        };
        for since in [
            peer.input.since.filter(|_| peer.final_report.is_none()),
            peer.output.front().map(|o| o.since),
        ]
        .into_iter()
        .flatten()
        {
            let at = since.checked_add(timeout).unwrap_or(since);
            deadline = Some(deadline.map_or(at, |old| old.min(at)));
        }
        if let Some((header, since)) = peer.final_report {
            let at = since
                + if header.kind == wire::END {
                    timeout.max(wire::TEARDOWN_TIMEOUT)
                } else {
                    timeout
                };
            deadline = Some(deadline.map_or(at, |old| old.min(at)));
        }
        if let Some(at) = deadline {
            self.deadlines.insert((at, token));
        }
        peer.deadline = deadline;
    }

    fn drop_tcp(&mut self, token: Token, peer: Peer, kind: Kind) {
        self.peers.release_taken(token);
        self.ending.remove(&token);
        self.ready.remove(&token);
        net::remove(&self.poll, peer.socket.as_raw_fd());
        if let Some(deadline) = peer.deadline {
            self.deadlines.remove(&(deadline, token));
        }
        self.budget.give(peer.input.frame.len() + peer.queued);
        self.buffers.give(peer.input.frame);
        for output in peer.output {
            self.buffers.give(output.bytes);
        }
        let h = lifecycle(
            peer.role.run().map(|r| r.as_ref()),
            match peer.role {
                Role::Data { flow, .. } => flow,
                _ => 0,
            },
        );
        self.outcome(peer.role.run(), h, kind);
        if kind != Kind::Closed && peer.role.run().is_some() {
            self.record(peer.role.run().unwrap(), h, Kind::Closed);
        }
        match peer.role {
            Role::Pending => {
                self.shared.pending.fetch_sub(1, Ordering::AcqRel);
            }
            Role::Control { run, .. } => {
                self.shared.end(&run);
                self.shared.controls.fetch_sub(1, Ordering::AcqRel);
            }
            Role::Data { run, flow } => {
                // Publish before ACTIVE's release so a final report on another
                // worker observes all traffic when it acquires ACTIVE == 0.
                self.publish_run(&run);
                self.shared.release(&run, flow);
                if let Some(local) = self.local.get_mut(&run.id) {
                    local.tcp.remove(&token);
                }
            }
        }
    }

    fn queue_udp(&mut self, key: Key, bytes: Vec<u8>, h: Header) -> Result<(), Vec<u8>> {
        let needs_ticket = self.datagrams.get(&key).unwrap().ticket.is_none();
        if needs_ticket {
            let ticket = self.udp_ticket;
            self.udp_ticket = self.udp_ticket.wrapping_add(1);
            if !self.udp_ready.push_back(UdpReady { ticket, key }) {
                return Err(bytes);
            }
            self.datagrams.get_mut(&key).unwrap().ticket = Some(ticket);
        }
        let peer = self.datagrams.get_mut(&key).unwrap();
        peer.queued += bytes.len();
        peer.output
            .push_back(Output::new(bytes, h, Some(peer.run.clone())));
        Ok(())
    }

    fn finish_udp_output(&mut self, ticket: u64, key: Key, failure: Option<Kind>) {
        let _ = self.udp_ready.remove(&UdpReady { ticket, key });
        let peer = self.datagrams.get_mut(&key).unwrap();
        peer.ticket = None;
        let output = peer.output.pop_front().unwrap();
        peer.queued -= output.bytes.len();
        self.budget.give(output.bytes.len());
        if !peer.output.is_empty() {
            let next = self.udp_ticket;
            self.udp_ticket = self.udp_ticket.wrapping_add(1);
            peer.ticket = Some(next);
            assert!(self.udp_ready.push_back(UdpReady { ticket: next, key }));
        }
        if let Some(kind) = failure {
            self.outcome(output.run.as_ref(), output.h, kind);
        } else {
            self.sent(&output);
        }
        self.buffers.give(output.bytes);
    }

    fn udp_packet(&mut self, addr: SocketAddr, bytes: &[u8]) -> io::Result<()> {
        let h = match wire::parse(bytes) {
            Ok(h) if !h.tcp => h,
            _ => {
                self.shared.counts.add(INVALID, 1);
                return Ok(());
            }
        };
        let key = Key {
            addr,
            run: h.run,
            flow: h.flow,
        };
        if h.kind == wire::OPEN {
            let Some(run) = self.shared.lookup(h.run) else {
                self.shared.counts.add(INVALID, 1);
                return Ok(());
            };
            if !valid_open(h) || !run.matches(h) || h.aux as usize != run.length {
                self.outcome(Some(&run), h, Kind::Invalid);
                return Ok(());
            }
            if !self.datagrams.contains_key(&key) {
                if !self.local_run(&run)? {
                    self.outcome(Some(&run), h, Kind::Limited);
                    return Ok(());
                }
                if let Err(kind) = self.shared.admit(&run, h.flow, self.id) {
                    self.outcome(Some(&run), h, kind);
                    return Ok(());
                }
                self.local.get_mut(&run.id).unwrap().udp.insert(h.flow, key);
                self.datagrams.insert(
                    key,
                    UdpPeer {
                        run: run.clone(),
                        output: VecDeque::new(),
                        queued: 0,
                        ticket: None,
                    },
                );
                self.record(&run, h, Kind::Open);
            }
            let peer = self.datagrams.get(&key).unwrap();
            if peer.queued + wire::HEADER > PEER_BYTES || !self.budget.take(wire::HEADER) {
                self.outcome(Some(&run), h, Kind::Limited);
                return Ok(());
            }
            let ack = Header {
                kind: wire::ACK,
                ..h
            };
            let mut bytes = self.buffers.take(ack.len);
            ack.encode_into(&mut bytes);
            if let Err(bytes) = self.queue_udp(key, bytes, ack) {
                self.budget.give(bytes.len());
                self.buffers.give(bytes);
                self.outcome(Some(&run), h, Kind::Limited);
            }
            return Ok(());
        }
        let Some(peer) = self.datagrams.get(&key) else {
            // UDP CLOSE and the reliable control batch can arrive in either
            // order. Already-retired or unknown CLOSEs are harmless no-ops.
            if h.kind == wire::CLOSE && h.len == wire::HEADER {
                return Ok(());
            }
            if let Some(run) = self.shared.lookup(h.run) {
                self.outcome(Some(&run), h, Kind::Invalid);
            } else {
                self.shared.counts.add(INVALID, 1);
            }
            return Ok(());
        };
        let run = peer.run.clone();
        if !run.matches(h) {
            self.drop_udp(key, Kind::Closed);
            return Ok(());
        }
        if h.kind == wire::CLOSE && h.len == wire::HEADER {
            self.drop_udp(key, Kind::Closed);
        } else if h.kind == wire::DATA && h.len == run.length {
            self.request(h);
            self.defer_udp(key, bytes, h, Instant::now());
        } else {
            self.outcome(Some(&run), h, Kind::Invalid);
        }
        Ok(())
    }

    fn defer_udp(&mut self, key: Key, bytes: &[u8], h: Header, since: Instant) {
        let peer = &self.datagrams[&key];
        if bytes.len() > PEER_BYTES.saturating_sub(peer.queued) || !self.budget.take(bytes.len()) {
            let run = peer.run.clone();
            self.outcome(Some(&run), h, Kind::Limited);
            return;
        }
        let mut reply = self.buffers.take(bytes.len());
        reply.copy_from_slice(bytes);
        if let Err(reply) = self.queue_udp(key, reply, h) {
            self.budget.give(reply.len());
            self.buffers.give(reply);
            let run = self.datagrams[&key].run.clone();
            self.outcome(Some(&run), h, Kind::Limited);
        } else {
            self.datagrams
                .get_mut(&key)
                .unwrap()
                .output
                .back_mut()
                .unwrap()
                .since = since;
        }
    }

    fn echo_udp_batch<'b>(
        &mut self,
        packets: impl Iterator<Item = (SocketAddr, &'b [u8])>,
        mut send: impl FnMut(&UdpSocket, &[(SocketAddr, &[u8])]) -> io::Result<usize>,
    ) -> io::Result<()> {
        let mut replies = [(net::any(false, 0), &[][..]); BATCH_SIZE];
        let mut headers = [None; BATCH_SIZE];
        let mut count = 0;
        for (addr, bytes) in packets {
            let header = wire::parse(bytes).ok().filter(|h| {
                if h.tcp || h.kind != wire::DATA || !self.udp_writable {
                    return false;
                }
                let key = Key {
                    addr,
                    run: h.run,
                    flow: h.flow,
                };
                self.datagrams.get(&key).is_some_and(|peer| {
                    peer.output.is_empty() && h.len == peer.run.length && peer.run.matches(*h)
                })
            });
            if let Some(h) = header {
                replies[count] = (addr, bytes);
                headers[count] = Some(h);
                count += 1;
                if count == BATCH_SIZE {
                    self.echo_udp_with(&replies[..count], &headers[..count], &mut send)?;
                    count = 0;
                }
            } else {
                // Resolve borrowed DATA before OPEN/CLOSE or any slow path can
                // change ownership or queue order for a flow in this batch.
                if count != 0 {
                    self.echo_udp_with(&replies[..count], &headers[..count], &mut send)?;
                    count = 0;
                }
                self.udp_packet(addr, bytes)?;
            }
        }
        if count != 0 {
            self.echo_udp_with(&replies[..count], &headers[..count], &mut send)?;
        }
        Ok(())
    }

    fn echo_udp_with(
        &mut self,
        packets: &[(SocketAddr, &[u8])],
        headers: &[Option<Header>],
        send: &mut impl FnMut(&UdpSocket, &[(SocketAddr, &[u8])]) -> io::Result<usize>,
    ) -> io::Result<()> {
        let since = Instant::now();
        for h in headers.iter().flatten() {
            self.data_event(*h, Kind::ServerRequest);
        }
        let first_unsent = match send(&self.udp, packets) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "empty sendmmsg result",
                ))
            }
            Ok(sent) if sent > packets.len() => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "sendmmsg returned more packets than submitted",
                ));
            }
            Ok(sent) => {
                for h in headers[..sent].iter().flatten() {
                    self.data_event(*h, Kind::ServerResponse);
                }
                sent
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.udp_writable = false;
                0
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => 0,
            Err(_) => {
                let h = headers[0].unwrap();
                let run = self.local[&h.run].run.clone();
                self.outcome(Some(&run), h, Kind::Failed);
                1
            }
        };
        for ((addr, bytes), h) in packets[first_unsent..].iter().zip(&headers[first_unsent..]) {
            let h = h.unwrap();
            self.defer_udp(
                Key {
                    addr: *addr,
                    run: h.run,
                    flow: h.flow,
                },
                bytes,
                h,
                since,
            );
        }
        Ok(())
    }

    fn read_udp(&mut self, batch: &mut RecvBatch, sends: &mut SendBatch) -> io::Result<bool> {
        for _ in 0..QUANTUM / BATCH_SIZE {
            match batch.recv(&self.udp) {
                Ok(_) => {
                    if batch.truncated() != 0 {
                        self.shared.counts.add(INVALID, batch.truncated() as u64);
                    }
                    self.echo_udp_batch(batch.packets(), |socket, packets| {
                        sends.send(socket, packets)
                    })?;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(false),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(true)
    }

    fn flush_udp(&mut self, batch: &mut SendBatch) -> io::Result<()> {
        self.flush_udp_with(|socket, packets| batch.send(socket, packets))
    }

    fn flush_udp_with(
        &mut self,
        mut send: impl FnMut(&UdpSocket, &[(SocketAddr, &[u8])]) -> io::Result<usize>,
    ) -> io::Result<()> {
        let mut processed = 0;
        while self.udp_writable && processed < QUANTUM && !self.udp_ready.is_empty() {
            let limit = (QUANTUM - processed).min(BATCH_SIZE);
            let mut selected = [None; BATCH_SIZE];
            let mut count = 0;
            for _ in 0..limit {
                let Some(item) = self.udp_ready.pop_front() else {
                    break;
                };
                let ticket = item.ticket;
                let key = item.key;
                let Some(peer) = self.datagrams.get(&key) else {
                    processed += 1;
                    continue;
                };
                if peer.ticket != Some(ticket) || peer.output.is_empty() {
                    processed += 1;
                    continue;
                }
                if !peer.run.active() {
                    self.drop_udp(key, Kind::Closed);
                    processed += 1;
                } else if peer.output.front().unwrap().since.elapsed() >= peer.run.timeout {
                    self.finish_udp_output(ticket, key, Some(Kind::Limited));
                    processed += 1;
                } else {
                    selected[count] = Some(item);
                    count += 1;
                }
            }
            if count == 0 {
                continue;
            }
            let mut packets = [(net::any(false, 0), &[][..]); BATCH_SIZE];
            for (packet, item) in packets.iter_mut().zip(selected.iter().flatten()) {
                *packet = (
                    item.key.addr,
                    &self.datagrams[&item.key].output.front().unwrap().bytes[..],
                );
            }
            match send(&self.udp, &packets[..count]) {
                Ok(0) => {
                    for item in selected.into_iter().flatten().rev() {
                        self.udp_ready.push_front(item);
                    }
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "empty sendmmsg result",
                    ));
                }
                Ok(sent) => {
                    if sent > count {
                        for item in selected.into_iter().flatten().rev() {
                            self.udp_ready.push_front(item);
                        }
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "sendmmsg returned more packets than submitted",
                        ));
                    }
                    // Only this prefix left the kernel. Keep the suffix queued
                    // with its original ownership, budget, and timeout.
                    for item in selected.iter().flatten().take(sent) {
                        self.finish_udp_output(item.ticket, item.key, None);
                    }
                    for item in selected[sent..count].iter().flatten().rev() {
                        self.udp_ready.push_front(*item);
                    }
                    processed += sent;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    for item in selected.into_iter().flatten().rev() {
                        self.udp_ready.push_front(item);
                    }
                    self.udp_writable = false;
                    break;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                    for item in selected.into_iter().flatten().rev() {
                        self.udp_ready.push_front(item);
                    }
                    break;
                }
                Err(_) => {
                    let first = selected[0].unwrap();
                    self.finish_udp_output(first.ticket, first.key, Some(Kind::Failed));
                    for item in selected[1..count].iter().flatten().rev() {
                        self.udp_ready.push_front(*item);
                    }
                    processed += 1;
                }
            }
        }
        let interest = !self.udp_ready.is_empty() && !self.udp_writable;
        if interest != self.udp_write_interest {
            net::update(
                &self.poll,
                self.udp.as_raw_fd(),
                UDP,
                if interest {
                    Interest::READABLE | Interest::WRITABLE
                } else {
                    Interest::READABLE
                },
            )?;
            self.udp_write_interest = interest;
        }
        Ok(())
    }

    fn drop_udp(&mut self, key: Key, kind: Kind) {
        if let Some(peer) = self.datagrams.remove(&key) {
            if let Some(ticket) = peer.ticket {
                let _ = self.udp_ready.remove(&UdpReady { ticket, key });
            }
            self.budget.give(peer.queued);
            for output in peer.output {
                self.buffers.give(output.bytes);
            }
            self.outcome(Some(&peer.run), lifecycle(Some(&peer.run), key.flow), kind);
            self.publish_run(&peer.run);
            self.shared.release(&peer.run, key.flow);
            if let Some(local) = self.local.get_mut(&key.run) {
                local.udp.remove(&key.flow);
            }
        }
    }

    fn maintenance(&mut self) -> io::Result<()> {
        let ending: Vec<_> = self.ending.iter().copied().collect();
        for token in ending {
            if let Some(peer) = self.peers.get_mut(token) {
                if !peer.scheduled {
                    peer.scheduled = true;
                    let _ = self.ready.push_back(token);
                }
            }
        }
        let retirements = {
            let mut queue = self.shared.retirements[self.id].lock().unwrap();
            std::mem::take(&mut *queue)
        };
        for (run, flow) in retirements {
            let key = self
                .local
                .get(&run.id)
                .filter(|local| Arc::ptr_eq(&local.run, &run))
                .and_then(|local| local.udp.get(&flow))
                .copied();
            if let Some(key) = key {
                self.drop_udp(key, Kind::Closed);
            }
            self.publish_run(&run);
            self.shared
                .queued_retirements
                .fetch_sub(1, Ordering::AcqRel);
            if run.retiring.fetch_sub(1, Ordering::AcqRel) == 1 {
                self.shared.wake_workers();
            }
        }
        self.shared.expire();
        let now = Instant::now();
        // Only inspect the at-most-16 runs. Peer walks happen once, on teardown.
        let expired: Vec<_> = self
            .local
            .iter()
            .filter(|(_, local)| !local.run.active())
            .map(|(&id, _)| id)
            .collect();
        for id in expired {
            let local = self.local.get(&id).unwrap();
            let tcp: Vec<_> = local.tcp.iter().copied().collect();
            let udp: Vec<_> = local.udp.values().copied().collect();
            for token in tcp {
                if let Some(peer) = self.peers.remove(token) {
                    self.drop_tcp(token, peer, Kind::Closed);
                }
            }
            for key in udp {
                self.drop_udp(key, Kind::Closed);
            }
            self.publish_run(&self.local[&id].run);
            let local = self.local.remove(&id).unwrap();
            let Some(finalize) = &self.finalize else {
                local.recorder.finish()?;
                continue;
            };
            match finalize.try_send(local.recorder) {
                Ok(()) => {}
                Err(mpsc::TrySendError::Full(recorder)) => {
                    self.local.insert(id, LocalRun { recorder, ..local });
                }
                Err(mpsc::TrySendError::Disconnected(_)) => {
                    return Err(io::Error::other("recording finalizer stopped"))
                }
            }
        }
        while let Some(&(deadline, token)) = self.deadlines.first() {
            if deadline > now {
                break;
            }
            self.deadlines.pop_first();
            if let Some(peer) = self.peers.get_mut(token) {
                if peer.report_ready() {
                    peer.deadline = None;
                    if !peer.scheduled {
                        peer.scheduled = true;
                        let _ = self.ready.push_back(token);
                    }
                    continue;
                }
            }
            if let Some(peer) = self.peers.remove(token) {
                self.drop_tcp(token, peer, Kind::Failed);
            }
        }
        Ok(())
    }

    fn network_loop(&mut self) -> io::Result<()> {
        let mut events = Events::with_capacity(1024);
        let mut udp_buf = RecvBatch::default();
        let mut udp_send = SendBatch::default();
        let mut accepting = false;
        let mut receiving = false;
        let mut tick = Instant::now();
        let mut publish = tick;
        let mut report = tick;
        let mut previous = [0u64; 8];
        while !self.stop.load(Ordering::Acquire) {
            let runnable = accepting
                || receiving
                || !self.ready.is_empty()
                || (self.udp_writable && !self.udp_ready.is_empty());
            let mut deadline = tick;
            if let Some(&(at, _)) = self.deadlines.first() {
                deadline = deadline.min(at);
            }
            let timeout = if runnable {
                Duration::ZERO
            } else {
                net::timeout(deadline)
            };
            match self.poll.poll(&mut events, Some(timeout)) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
            for event in events.iter() {
                match event.token() {
                    WAKE => tick = Instant::now(),
                    LISTENER => accepting = true,
                    UDP => {
                        receiving |= event.is_readable();
                        self.udp_writable |= event.is_writable();
                    }
                    token => {
                        if let Some(peer) = self.peers.get_mut(token) {
                            peer.readable |=
                                event.is_readable() || event.is_read_closed() || event.is_error();
                            peer.writable |=
                                event.is_writable() || event.is_write_closed() || event.is_error();
                            if !peer.scheduled {
                                peer.scheduled = true;
                                let _ = self.ready.push_back(token);
                            }
                        }
                    }
                }
            }
            if accepting {
                accepting = self.accept_connections()?;
            }
            if receiving {
                receiving = self.read_udp(&mut udp_buf, &mut udp_send)?;
            }
            for _ in 0..QUANTUM {
                let Some(token) = self.ready.pop_front() else {
                    break;
                };
                let Some(mut peer) = self.peers.take(token) else {
                    continue;
                };
                peer.scheduled = false;
                match self.service_tcp(token, &mut peer) {
                    Ok(Ok(again)) => {
                        self.deadline(token, &mut peer);
                        if again {
                            peer.scheduled = true;
                            let _ = self.ready.push_back(token);
                        }
                        assert!(self.peers.put(token, peer));
                    }
                    Ok(Err(kind)) => self.drop_tcp(token, peer, kind),
                    Err(e) => {
                        self.drop_tcp(token, peer, Kind::Failed);
                        return Err(e);
                    }
                }
            }
            self.flush_udp(&mut udp_send)?;
            let now = Instant::now();
            if now >= publish {
                self.publish_traffic();
                publish = now + PUBLISH;
            }
            if now >= tick || self.deadlines.first().is_some_and(|&(at, _)| at <= now) {
                self.maintenance()?;
                tick = Instant::now() + TICK;
            }
            if self.o.server_stats
                && self.id == 0
                && now.duration_since(report) >= Duration::from_secs(1)
            {
                let current = self.shared.snapshot();
                let dt = now.duration_since(report).as_secs_f64();
                eprintln!("server clients={} active={} request/s={:.0} response/s={:.0} rx_Mbit/s={:.3} tx_Mbit/s={:.3} failed={} limited={} invalid={}",
                    self.shared.controls.load(Ordering::Relaxed), current[ACTIVE],
                    current[REQUESTS].saturating_sub(previous[REQUESTS]) as f64 / dt,
                    current[RESPONSES].saturating_sub(previous[RESPONSES]) as f64 / dt,
                    current[REQUEST_BYTES].saturating_sub(previous[REQUEST_BYTES]) as f64 * 8.0 / dt / 1e6,
                    current[RESPONSE_BYTES].saturating_sub(previous[RESPONSE_BYTES]) as f64 * 8.0 / dt / 1e6,
                    current[FAILED], current[LIMITED], current[INVALID]);
                previous = current;
                report = now;
            }
        }
        Ok(())
    }

    fn finish(&mut self) -> io::Result<()> {
        for token in self.peers.tokens() {
            let peer = self.peers.remove(token).unwrap();
            self.drop_tcp(token, peer, Kind::Closed);
        }
        while let Some(key) = self.datagrams.keys().next().copied() {
            self.drop_udp(key, Kind::Closed);
        }
        self.publish_traffic();
        let mut result = Ok(());
        for (_, local) in self.local.drain() {
            if let Some(finalize) = &self.finalize {
                if finalize.send(local.recorder).is_err() {
                    result = Err(io::Error::other("recording finalizer stopped"));
                }
            } else if let Err(error) = local.recorder.finish() {
                result = Err(error);
            }
        }
        self.finalize.take();
        if let Some(finalizer) = self.finalizer.take() {
            let finished = finalizer
                .join()
                .map_err(|_| io::Error::other("recording finalizer panicked"))?;
            if result.is_ok() {
                result = finished;
            }
        }
        debug_assert_eq!(self.budget.used, 0);
        result
    }
}

impl Drop for Worker<'_> {
    fn drop(&mut self) {
        self.publish_traffic();
    }
}

fn listener_udp(o: &Config) -> io::Result<UdpSocket> {
    Ok(listener(o, false)?.into())
}

fn valid_open(h: Header) -> bool {
    h.kind == wire::OPEN && h.len == wire::HEADER && h.seq == 0 && h.stamp == 0
}

fn lifecycle(run: Option<&Run>, flow: u64) -> Header {
    Header {
        kind: wire::CLOSE,
        tcp: run.is_some_and(|r| r.tcp),
        run: run.map_or(0, |r| r.id),
        flow,
        seq: 0,
        stamp: 0,
        aux: 0,
        len: wire::HEADER,
    }
}

pub fn run(o: &Config, stop: Arc<AtomicBool>) -> io::Result<()> {
    if o.workers == 0 || o.timeout.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "server needs positive workers and timeout",
        ));
    }
    crate::ports::preflight(o, 0)?;
    std::fs::create_dir_all(&o.output)?;
    let shared = Arc::new(Shared::new(o.workers));
    let mut initialized = Vec::with_capacity(o.workers);
    for id in 0..o.workers {
        match Worker::new(o, id, shared.clone(), stop.clone()) {
            Ok(worker) => initialized.push(worker),
            Err(e) => {
                for worker in &mut initialized {
                    let _ = worker.finish();
                }
                return Err(e);
            }
        }
    }
    let announced = (|| {
        let mut stdout = io::stdout().lock();
        writeln!(
            stdout,
            "flowgen server | {} | {} workers | TCP+UDP",
            net::any(o.ipv6, o.port),
            o.workers
        )?;
        writeln!(stdout, "records: {}", o.output.display())?;
        if o.send_buffer.is_some() || o.recv_buffer.is_some() {
            let worker = &initialized[0];
            let (send, receive) = tuning::effective_buffers(&worker.listener)?;
            let udp = socket2::SockRef::from(&worker.udp);
            writeln!(stdout,
                "socket buffers (kernel bytes): TCP send={send} recv={receive}; UDP send={} recv={}",
                udp.send_buffer_size()?, udp.recv_buffer_size()?)?;
        }
        stdout.flush()
    })();
    if let Err(e) = announced {
        for worker in &mut initialized {
            let _ = worker.finish();
        }
        return Err(e);
    }
    thread::scope(|scope| {
        let mut workers = Vec::with_capacity(o.workers);
        for mut worker in initialized {
            let stop = stop.clone();
            workers.push(scope.spawn(move || {
                let _stop_on_exit = StopOnExit(stop.clone());
                if let Err(error) = tuning::pin_worker(o, worker.id) {
                    stop.store(true, Ordering::Release);
                    return Err(error);
                }
                let result = worker.network_loop();
                if result.is_err() {
                    stop.store(true, Ordering::Release);
                }
                let finished = worker.finish();
                result.and(finished)
            }));
        }
        let mut result = Ok(());
        for worker in workers {
            let finished = worker.join().unwrap_or_else(|_| {
                stop.store(true, Ordering::Release);
                Err(io::Error::other("server worker panicked"))
            });
            if result.is_ok() {
                result = finished;
            }
        }
        result
    })
}

struct StopOnExit(Arc<AtomicBool>);

impl Drop for StopOnExit {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(name: &str) -> Config {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "flowgen-server-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut o = crate::options::parse(vec![
            "-s".into(),
            "-w".into(),
            "2".into(),
            "-o".into(),
            path.to_string_lossy().into_owned(),
        ])
        .unwrap();
        o.port = 0;
        std::fs::create_dir_all(&o.output).unwrap();
        o
    }

    fn pending(socket: Socket) -> Peer {
        Peer {
            socket,
            role: Role::Pending,
            input: Input::default(),
            output: VecDeque::new(),
            queued: 0,
            accepted: Instant::now(),
            deadline: None,
            readable: true,
            writable: true,
            write_interest: false,
            scheduled: false,
            closing: false,
            final_report: None,
            teardown_deadline: None,
        }
    }

    fn control(run: u64, target: u64) -> Header {
        Header {
            kind: wire::CONTROL,
            tcp: true,
            run,
            flow: target,
            seq: 1_000_000_000,
            stamp: 60_000_000_000,
            aux: 128,
            len: wire::HEADER,
        }
    }

    #[test]
    fn unlimited_control_has_no_expiry_but_still_ends() {
        let o = test_config("unlimited");
        let shared = Arc::new(Shared::new(2));
        let run = shared
            .accept(Header {
                stamp: wire::UNLIMITED_RUN,
                ..control(42, 1)
            })
            .ok()
            .unwrap();
        assert!(run.expires.is_none());
        shared.expire();
        assert!(shared.lookup(42).is_some());
        let mut worker =
            Worker::new(&o, 0, shared.clone(), Arc::new(AtomicBool::new(false))).unwrap();
        let (tx, _rx) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut peer = pending(tx.into());
        peer.role = Role::Control {
            run: run.clone(),
            last_seq: None,
            ended: false,
        };
        worker.deadline(Token(2), &mut peer);
        assert!(peer.deadline.is_none());
        // Partial frames retain their timeout even on an unlimited control.
        let since = Instant::now();
        peer.input.since = Some(since);
        worker.deadline(Token(2), &mut peer);
        assert_eq!(peer.deadline, Some(since + run.timeout));
        shared.end(&run);
        assert!(!run.active());
        assert!(shared.lookup(42).is_none());
        let finite = shared.accept(control(43, 1)).ok().unwrap();
        assert_eq!(finite.expires, Some(finite.start + Duration::from_secs(60)));
        drop(worker);
        std::fs::remove_dir_all(&o.output).unwrap();
    }

    #[test]
    fn sharded_traffic_is_exact_across_workers_and_run_retirement() {
        let shared = Arc::new(Shared::new(8));
        let run = shared.accept(control(123, 10000)).ok().unwrap();
        thread::scope(|scope| {
            for id in 0..8 {
                let shared = &shared;
                let run = &run;
                scope.spawn(move || {
                    let counters = LocalTraffic::default();
                    for _ in 0..10000 {
                        for (index, value) in [
                            (REQUESTS, 1),
                            (RESPONSES, 1),
                            (REQUEST_BYTES, 128),
                            (RESPONSE_BYTES, 128),
                        ] {
                            counters.add(index, value);
                        }
                    }
                    counters.publish(&run.traffic[id]);
                    counters.publish(&shared.traffic[id]);
                });
            }
        });
        let expected = [80000, 80000, 10240000, 10240000, 0, 0, 0, 0];
        assert_eq!(run.snapshot(), expected);
        assert_eq!(shared.snapshot(), expected);
        shared.end(&run);
        assert_eq!(shared.snapshot(), expected);
        let next = shared.accept(control(124, 1)).ok().unwrap();
        assert_eq!(next.snapshot(), [0; 8]);
    }

    #[test]
    fn final_report_waits_for_data_owners_and_freezes_admissions() {
        use std::io::Read;
        let o = test_config("final-report");
        let shared = Arc::new(Shared::new(2));
        let run = shared.accept(control(42, 1)).ok().unwrap();
        shared.admit(&run, 1, 1).unwrap();
        let mut worker =
            Worker::new(&o, 0, shared.clone(), Arc::new(AtomicBool::new(false))).unwrap();
        let (tx, mut rx) = std::os::unix::net::UnixStream::pair().unwrap();
        tx.set_nonblocking(true).unwrap();
        rx.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let mut peer = pending(tx.into());
        peer.readable = false;
        peer.role = Role::Control {
            run: run.clone(),
            last_seq: None,
            ended: false,
        };
        let end = Header {
            kind: wire::END,
            seq: 1,
            ..control(42, 1)
        };
        assert!(worker.budget.take(end.len));
        let token = Token(2);
        net::register(
            &worker.poll,
            peer.socket.as_raw_fd(),
            token,
            Interest::READABLE,
        )
        .unwrap();
        assert!(worker
            .frame(token, &mut peer, end.encode())
            .unwrap()
            .is_ok());
        assert!(!run.active());
        assert_eq!(shared.admit(&run, 2, 1), Err(Kind::Invalid));
        assert!(worker.service_tcp(token, &mut peer).unwrap().is_ok());
        assert!(peer.final_report.is_some());
        assert!(peer.output.is_empty());
        let end_deadline = peer.teardown_deadline;
        worker.deadline(token, &mut peer);
        assert_eq!(peer.deadline, end_deadline);
        let counters = LocalTraffic::default();
        counters.add(REQUESTS, 7);
        counters.add(RESPONSES, 6);
        counters.publish(&run.traffic[1]);
        shared.release(&run, 1);
        worker.outcome(Some(&run), end, Kind::Invalid);
        assert_eq!(run.snapshot()[INVALID], 0, "post-cutoff error mutated run");
        assert_eq!(
            shared.snapshot()[INVALID],
            1,
            "post-cutoff error disappeared"
        );
        peer.writable = false;
        assert!(worker.service_tcp(token, &mut peer).unwrap().is_ok());
        assert!(peer.final_report.is_none());
        assert_eq!(peer.output.len(), 1);
        peer.input.since = Some(Instant::now() - run.timeout * 2);
        worker.deadline(token, &mut peer);
        assert_eq!(
            peer.deadline, end_deadline,
            "blocked final output shortened teardown timeout"
        );
        peer.writable = true;
        assert_eq!(
            worker.service_tcp(token, &mut peer).unwrap(),
            Err(Kind::Closed)
        );
        let mut bytes = [0; wire::REPORT_LEN];
        rx.read_exact(&mut bytes).unwrap();
        let report = wire::counters(&bytes).unwrap();
        assert_eq!(report[REQUESTS], 7);
        assert_eq!(report[RESPONSES], 6);
        assert_eq!(report[ACTIVE], 0);
        assert!(worker.ending.is_empty());
        worker.drop_tcp(token, peer, Kind::Closed);
        worker.finish().unwrap();
        std::fs::remove_dir_all(&o.output).unwrap();
    }

    fn ready_udp(worker: &mut Worker<'_>, count: usize) -> Arc<Run> {
        let h = Header {
            tcp: false,
            ..control(99, count as u64)
        };
        let run = worker.shared.accept(h).ok().unwrap();
        for flow in 1..=count as u64 {
            let addr = SocketAddr::from(([127, 0, 0, 1], 20000 + flow as u16));
            let open = Header {
                kind: wire::OPEN,
                flow,
                seq: 0,
                stamp: 0,
                ..h
            };
            worker.udp_packet(addr, &open.encode()).unwrap();
        }
        worker
            .flush_udp_with(|_, packets| Ok(packets.len()))
            .unwrap();
        run
    }

    fn udp_data(flow: u64, seq: u64) -> (SocketAddr, Vec<u8>) {
        (
            SocketAddr::from(([127, 0, 0, 1], 20000 + flow as u16)),
            Header {
                kind: wire::DATA,
                tcp: false,
                flow,
                seq,
                len: 128,
                ..control(99, 1)
            }
            .encode(),
        )
    }

    fn queued_udp(worker: &mut Worker<'_>, count: usize) -> Arc<Run> {
        let run = ready_udp(worker, count);
        for flow in 1..=count as u64 {
            let (addr, data) = udp_data(flow, 1);
            worker.udp_packet(addr, &data).unwrap();
        }
        run
    }

    #[test]
    fn direct_udp_borrows_payloads_and_publishes_only_when_requested() {
        let mut o = test_config("udp-direct");
        o.recording = "off".into();
        let shared = Arc::new(Shared::new(1));
        let mut worker =
            Worker::new(&o, 0, shared.clone(), Arc::new(AtomicBool::new(false))).unwrap();
        let run = ready_udp(&mut worker, 3);
        let refs = Arc::strong_count(&run);
        let data: Vec<_> = (1..=3).map(|flow| udp_data(flow, 7)).collect();
        let mut calls = 0;
        worker
            .echo_udp_batch(
                data.iter().map(|(addr, bytes)| (*addr, bytes.as_slice())),
                |_, packets| {
                    calls += 1;
                    assert_eq!(Arc::strong_count(&run), refs);
                    for ((addr, bytes), (expected_addr, expected)) in packets.iter().zip(&data) {
                        assert_eq!(addr, expected_addr);
                        assert_eq!(bytes.as_ptr(), expected.as_ptr());
                        assert_eq!(*bytes, expected);
                    }
                    Ok(packets.len())
                },
            )
            .unwrap();
        assert_eq!(calls, 1);
        assert_eq!(&run.snapshot()[..4], &[0; 4]);
        assert_eq!(worker.budget.used, 0);
        assert!(worker.udp_ready.is_empty());
        worker.publish_traffic();
        let expected = [3, 3, 384, 384];
        assert_eq!(&run.snapshot()[..4], &expected);
        worker.publish_traffic();
        assert_eq!(&shared.snapshot()[..4], &expected);
        worker.finish().unwrap();
        assert_eq!(&run.snapshot()[..4], &expected);
        std::fs::remove_dir_all(&o.output).unwrap();
    }

    #[test]
    fn direct_udp_partial_send_queues_suffix_and_preserves_per_flow_order() {
        let o = test_config("udp-direct-partial");
        let shared = Arc::new(Shared::new(1));
        let mut worker = Worker::new(&o, 0, shared, Arc::new(AtomicBool::new(false))).unwrap();
        let run = ready_udp(&mut worker, 5);
        let data: Vec<_> = (1..=5).map(|flow| udp_data(flow, 1)).collect();
        worker
            .echo_udp_batch(
                data.iter().map(|(addr, bytes)| (*addr, bytes.as_slice())),
                |_, packets| {
                    assert_eq!(packets.len(), 5);
                    Ok(2)
                },
            )
            .unwrap();
        assert_eq!(worker.budget.used, 384);
        let (addr, next) = udp_data(3, 2);
        worker
            .echo_udp_batch(std::iter::once((addr, next.as_slice())), |_, _| {
                panic!("bypassed queued response")
            })
            .unwrap();
        assert_eq!(worker.budget.used, 512);
        let mut third = Vec::new();
        worker
            .flush_udp_with(|_, packets| {
                for (_, bytes) in packets {
                    let h = wire::parse(bytes).unwrap();
                    if h.flow == 3 {
                        third.push(h.seq);
                    }
                }
                Ok(packets.len())
            })
            .unwrap();
        assert_eq!(third, [1, 2]);
        worker.publish_traffic();
        assert_eq!(&run.snapshot()[..4], &[6, 6, 768, 768]);
        assert_eq!(worker.budget.used, 0);
        worker.finish().unwrap();
        std::fs::remove_dir_all(&o.output).unwrap();
    }

    #[test]
    fn direct_udp_errors_preserve_suffix_and_count_only_failed_first_packet() {
        for errno in [libc::EAGAIN, libc::EINTR, libc::EMSGSIZE] {
            let o = test_config("udp-direct-errors");
            let shared = Arc::new(Shared::new(1));
            let mut worker = Worker::new(&o, 0, shared, Arc::new(AtomicBool::new(false))).unwrap();
            let run = ready_udp(&mut worker, 3);
            let data: Vec<_> = (1..=3).map(|flow| udp_data(flow, 1)).collect();
            worker
                .echo_udp_batch(
                    data.iter().map(|(addr, bytes)| (*addr, bytes.as_slice())),
                    |_, _| Err(io::Error::from_raw_os_error(errno)),
                )
                .unwrap();
            let failed = u64::from(errno == libc::EMSGSIZE);
            assert_eq!(worker.budget.used, (3 - failed as usize) * 128);
            assert_eq!(worker.udp_writable, errno != libc::EAGAIN);
            worker.udp_writable = true;
            worker
                .flush_udp_with(|_, packets| Ok(packets.len()))
                .unwrap();
            worker.publish_traffic();
            assert_eq!(run.snapshot()[REQUESTS], 3);
            assert_eq!(run.snapshot()[RESPONSES], 3 - failed);
            assert_eq!(run.snapshot()[FAILED], failed);
            assert_eq!(worker.budget.used, 0);
            worker.finish().unwrap();
            std::fs::remove_dir_all(&o.output).unwrap();
        }
    }

    #[test]
    fn direct_udp_backpressure_still_obeys_worker_budget() {
        let o = test_config("udp-direct-budget");
        let shared = Arc::new(Shared::new(1));
        let mut worker = Worker::new(&o, 0, shared, Arc::new(AtomicBool::new(false))).unwrap();
        let run = ready_udp(&mut worker, 1);
        worker.budget.used = WORKER_BYTES;
        let (addr, bytes) = udp_data(1, 1);
        worker
            .echo_udp_batch(std::iter::once((addr, bytes.as_slice())), |_, _| {
                Err(io::Error::from_raw_os_error(libc::EAGAIN))
            })
            .unwrap();
        worker.publish_traffic();
        assert_eq!(run.snapshot()[REQUESTS], 1);
        assert_eq!(run.snapshot()[RESPONSES], 0);
        assert_eq!(run.snapshot()[LIMITED], 1);
        assert!(worker.udp_ready.is_empty());
        assert_eq!(worker.budget.used, WORKER_BYTES);
        worker.budget.used = 0;
        worker.finish().unwrap();
        std::fs::remove_dir_all(&o.output).unwrap();
    }

    #[test]
    fn direct_udp_full_batch_block_stops_further_direct_sends() {
        let o = test_config("udp-direct-full");
        let shared = Arc::new(Shared::new(1));
        let mut worker = Worker::new(&o, 0, shared, Arc::new(AtomicBool::new(false))).unwrap();
        let run = ready_udp(&mut worker, 1);
        let data: Vec<_> = (1..=40).map(|seq| udp_data(1, seq)).collect();
        let mut calls = 0;
        worker
            .echo_udp_batch(
                data.iter().map(|(addr, bytes)| (*addr, bytes.as_slice())),
                |_, packets| {
                    calls += 1;
                    assert_eq!(packets.len(), BATCH_SIZE);
                    Err(io::Error::from_raw_os_error(libc::EAGAIN))
                },
            )
            .unwrap();
        assert_eq!(calls, 1);
        assert_eq!(worker.budget.used, 40 * 128);
        assert_eq!(worker.udp_ready.len(), 1);
        worker.udp_writable = true;
        let mut sequences = Vec::new();
        worker
            .flush_udp_with(|_, packets| {
                sequences.extend(
                    packets
                        .iter()
                        .map(|(_, bytes)| wire::parse(bytes).unwrap().seq),
                );
                Ok(packets.len())
            })
            .unwrap();
        assert_eq!(sequences, (1..=40).collect::<Vec<_>>());
        worker.publish_traffic();
        assert_eq!(&run.snapshot()[..4], &[40, 40, 5120, 5120]);
        assert_eq!(worker.budget.used, 0);
        worker.finish().unwrap();
        std::fs::remove_dir_all(&o.output).unwrap();
    }

    #[test]
    fn direct_udp_flushes_before_close_and_rejects_later_or_foreign_data() {
        let o = test_config("udp-direct-close");
        let shared = Arc::new(Shared::new(1));
        let mut worker = Worker::new(&o, 0, shared, Arc::new(AtomicBool::new(false))).unwrap();
        let run = ready_udp(&mut worker, 1);
        let (addr, bytes) = udp_data(1, 1);
        let close = lifecycle(Some(&run), 1).encode();
        let packets = [
            (addr, bytes.as_slice()),
            (addr, close.as_slice()),
            (addr, bytes.as_slice()),
        ];
        worker
            .echo_udp_batch(packets.into_iter(), |_, packets| {
                assert_eq!(run.snapshot()[ACTIVE], 1);
                assert_eq!(packets.len(), 1);
                Ok(1)
            })
            .unwrap();
        assert_eq!(&run.snapshot()[..4], &[1, 1, 128, 128]);
        assert_eq!(run.snapshot()[ACTIVE], 0);
        assert_eq!(run.snapshot()[INVALID], 1);
        assert!(worker.datagrams.is_empty());
        worker.finish().unwrap();
        std::fs::remove_dir_all(&o.output).unwrap();
    }

    #[test]
    fn direct_udp_validates_address_run_length_and_type() {
        let o = test_config("udp-direct-invalid");
        let shared = Arc::new(Shared::new(1));
        let mut worker =
            Worker::new(&o, 0, shared.clone(), Arc::new(AtomicBool::new(false))).unwrap();
        let run = ready_udp(&mut worker, 1);
        let (addr, bytes) = udp_data(1, 1);
        let h = wire::parse(&bytes).unwrap();
        let wrong_addr = SocketAddr::from(([127, 0, 0, 2], addr.port()));
        let cases = [
            (wrong_addr, bytes),
            (addr, Header { run: 100, ..h }.encode()),
            (addr, Header { len: 129, ..h }.encode()),
            (addr, Header { tcp: true, ..h }.encode()),
            (addr, vec![0; 3]),
        ];
        worker
            .echo_udp_batch(
                cases.iter().map(|(addr, bytes)| (*addr, bytes.as_slice())),
                |_, _| panic!("invalid DATA echoed"),
            )
            .unwrap();
        worker.publish_traffic();
        assert_eq!(run.snapshot()[REQUESTS], 0);
        assert_eq!(shared.snapshot()[INVALID], 5);
        worker.finish().unwrap();
        std::fs::remove_dir_all(&o.output).unwrap();
    }

    #[test]
    fn local_traffic_is_published_before_run_removal_and_worker_drop() {
        let mut o = test_config("traffic-final");
        o.recording = "off".into();
        let shared = Arc::new(Shared::new(1));
        let mut worker =
            Worker::new(&o, 0, shared.clone(), Arc::new(AtomicBool::new(false))).unwrap();
        let run = queued_udp(&mut worker, 1);
        worker
            .flush_udp_with(|_, packets| Ok(packets.len()))
            .unwrap();
        assert_eq!(&run.snapshot()[..4], &[0; 4]);
        shared.end(&run);
        worker.maintenance().unwrap();
        assert!(worker.local.is_empty());
        assert_eq!(&run.snapshot()[..5], &[1, 1, 128, 128, 0]);
        assert_eq!(&shared.snapshot()[..5], &[1, 1, 128, 128, 0]);
        let next = queued_udp(&mut worker, 1);
        assert_eq!(&next.snapshot()[..4], &[0; 4]);
        worker.publish_run(&run);
        assert_eq!(&run.snapshot()[..4], &[1, 1, 128, 128]);
        drop(worker);
        assert_eq!(&next.snapshot()[..4], &[1, 0, 128, 0]);
        assert_eq!(&shared.snapshot()[..4], &[2, 1, 256, 128]);
        std::fs::remove_dir_all(&o.output).unwrap();
    }

    #[test]
    fn end_wakes_workers_and_teardown_precedes_short_report_timeout() {
        let o = test_config("end-short-timeout");
        let shared = Arc::new(Shared::new(1));
        let mut worker =
            Worker::new(&o, 0, shared.clone(), Arc::new(AtomicBool::new(false))).unwrap();
        let h = Header {
            tcp: false,
            seq: 1_000_000,
            ..control(777, 1)
        };
        let run = shared.accept(h).ok().unwrap();
        let addr = SocketAddr::from(([127, 0, 0, 1], 20999));
        worker
            .udp_packet(
                addr,
                &Header {
                    kind: wire::OPEN,
                    flow: 1,
                    seq: 0,
                    stamp: 0,
                    ..h
                }
                .encode(),
            )
            .unwrap();
        let (tx, _rx) = std::os::unix::net::UnixStream::pair().unwrap();
        tx.set_nonblocking(true).unwrap();
        let mut peer = pending(tx.into());
        peer.readable = false;
        peer.role = Role::Control {
            run: run.clone(),
            last_seq: None,
            ended: false,
        };
        let end = Header {
            kind: wire::END,
            seq: 1,
            ..h
        };
        assert!(worker.budget.take(end.len));
        let token = worker.peers.insert(peer).unwrap();
        let mut peer = worker.peers.take(token).unwrap();
        worker
            .frame(token, &mut peer, end.encode())
            .unwrap()
            .unwrap();
        let mut events = Events::with_capacity(8);
        worker.poll.poll(&mut events, Some(Duration::ZERO)).unwrap();
        assert!(events.iter().any(|event| event.token() == WAKE));
        peer.final_report.as_mut().unwrap().1 = Instant::now() - Duration::from_millis(30);
        worker.deadline(token, &mut peer);
        worker.peers.put(token, peer);
        worker.maintenance().unwrap();
        assert_eq!(run.snapshot()[ACTIVE], 0);
        assert!(worker.datagrams.is_empty());
        assert_eq!(run.snapshot()[FAILED], 0);
        let mut peer = worker.peers.take(token).unwrap();
        assert!(peer.final_report.is_some());
        assert!(worker.ready.contains(&token));
        assert_eq!(
            worker.service_tcp(token, &mut peer).unwrap(),
            Err(Kind::Closed)
        );
        worker.drop_tcp(token, peer, Kind::Closed);
        worker.finish().unwrap();
        std::fs::remove_dir_all(&o.output).unwrap();
    }

    #[test]
    fn udp_partial_batch_keeps_suffix_budget_and_retries_without_double_counting() {
        let o = test_config("udp-partial");
        let shared = Arc::new(Shared::new(1));
        let mut worker = Worker::new(&o, 0, shared, Arc::new(AtomicBool::new(false))).unwrap();
        let run = queued_udp(&mut worker, 5);
        let mut calls = 0;
        worker
            .flush_udp_with(|_, packets| {
                calls += 1;
                if calls == 1 {
                    assert_eq!(packets.len(), 5);
                    Ok(2)
                } else {
                    assert_eq!(packets.len(), 3);
                    assert_eq!(wire::parse(packets[0].1).unwrap().flow, 3);
                    Err(io::Error::from(io::ErrorKind::WouldBlock))
                }
            })
            .unwrap();
        worker.publish_traffic();
        assert_eq!(run.snapshot()[RESPONSES], 2);
        assert_eq!(worker.budget.used, 3 * 128);
        assert_eq!(worker.udp_ready.len(), 3);
        assert!(!worker.udp_writable);
        worker.udp_writable = true;
        worker
            .flush_udp_with(|_, _| Err(io::Error::from(io::ErrorKind::Interrupted)))
            .unwrap();
        assert_eq!(worker.budget.used, 3 * 128);
        assert!(worker.udp_writable);
        worker
            .flush_udp_with(|_, packets| Ok(packets.len()))
            .unwrap();
        worker.publish_traffic();
        assert_eq!(run.snapshot()[RESPONSES], 5);
        assert_eq!(worker.budget.used, 0);
        assert!(worker.udp_ready.is_empty());
        worker.finish().unwrap();
        std::fs::remove_dir_all(&o.output).unwrap();
    }

    #[test]
    fn udp_batch_error_charges_only_first_packet_and_expiration_remains_visible() {
        let o = test_config("udp-errors");
        let shared = Arc::new(Shared::new(1));
        let mut worker = Worker::new(&o, 0, shared, Arc::new(AtomicBool::new(false))).unwrap();
        let run = queued_udp(&mut worker, 5);
        let mut calls = 0;
        worker
            .flush_udp_with(|_, _| {
                calls += 1;
                Err(io::Error::from_raw_os_error(if calls == 1 {
                    libc::EMSGSIZE
                } else {
                    libc::EAGAIN
                }))
            })
            .unwrap();
        assert_eq!(run.snapshot()[FAILED], 1);
        assert_eq!(run.snapshot()[RESPONSES], 0);
        assert_eq!(worker.budget.used, 4 * 128);
        let item = worker.udp_ready.pop_front().unwrap();
        let key = item.key;
        let _ = worker.udp_ready.push_front(item);
        worker
            .datagrams
            .get_mut(&key)
            .unwrap()
            .output
            .front_mut()
            .unwrap()
            .since = Instant::now() - run.timeout;
        worker.udp_writable = true;
        worker
            .flush_udp_with(|_, packets| Ok(packets.len()))
            .unwrap();
        assert_eq!(run.snapshot()[LIMITED], 1);
        worker.publish_traffic();
        assert_eq!(run.snapshot()[RESPONSES], 3);
        assert_eq!(worker.budget.used, 0);
        worker.finish().unwrap();
        std::fs::remove_dir_all(&o.output).unwrap();
    }

    #[test]
    fn client_targets_do_not_reserve_capacity_but_control_limit_is_global() {
        let shared = Shared::new(2);
        let a = shared.accept(control(1, 12)).ok().unwrap();
        assert!(shared.accept(control(2, 1_000_000)).is_ok());
        assert!(matches!(shared.accept(control(1, 1)), Err(Kind::Invalid)));
        shared.end(&a);
        shared.controls.fetch_sub(1, Ordering::Relaxed);
        assert!(shared.accept(control(3, 12)).is_ok());
        let shared = Shared::new(2);
        for id in 1..=16 {
            assert!(shared.accept(control(id, 1)).is_ok());
        }
        assert!(matches!(shared.accept(control(17, 1)), Err(Kind::Limited)));
    }

    #[test]
    fn replacements_can_overlap_old_flows_but_never_resurrect_retired_ids() {
        let shared = Shared::new(2);
        let run = shared.accept(control(1, 2)).ok().unwrap();
        assert!(shared.admit(&run, 5, 0).is_ok());
        assert!(shared.admit(&run, 6, 1).is_ok());
        assert!(shared.admit(&run, 7, 1).is_ok());
        assert_eq!(run.counts.snapshot()[ACTIVE], 3);
        shared.release(&run, 5);
        shared.release(&run, 5);
        assert!(matches!(shared.admit(&run, 5, 0), Err(Kind::Invalid)));
        assert!(matches!(shared.admit(&run, 7, 0), Err(Kind::Invalid)));
        shared.end(&run);
        assert!(shared.lookup(1).is_none());
        assert!(matches!(shared.admit(&run, 8, 1), Err(Kind::Invalid)));
        shared.release(&run, 6);
        shared.release(&run, 7);
        assert_eq!(shared.active.load(Ordering::Relaxed), 0);
        assert_eq!(run.counts.snapshot()[ACTIVE], 0);
    }

    #[test]
    fn replay_history_is_bounded_and_preserves_live_out_of_order_ids() {
        let mut flows = Flows::new(2);
        flows.history = 4;
        flows.live.insert(
            1,
            FlowOwner {
                worker: 0,
                retiring: false,
            },
        );
        for id in 2..100 {
            assert!(flows.admissible(id));
            flows.live.insert(
                id,
                FlowOwner {
                    worker: 0,
                    retiring: false,
                },
            );
            assert!(flows.retire(id));
            assert!(flows.retired.len() <= 4);
        }
        assert!(!flows.admissible(10));
        assert!(flows.live.contains_key(&1));
        assert!(flows.retire(1));
        assert!(!flows.admissible(1));
    }

    #[test]
    fn reliable_retirement_routes_to_owner_and_is_idempotent() {
        use std::io::{Read, Write};
        let o = test_config("retirement");
        let shared = Arc::new(Shared::new(2));
        let stop = Arc::new(AtomicBool::new(false));
        let mut control_worker = Worker::new(&o, 0, shared.clone(), stop.clone()).unwrap();
        let mut data_worker = Worker::new(&o, 1, shared.clone(), stop).unwrap();
        let addr = control_worker
            .listener
            .local_addr()
            .unwrap()
            .as_socket()
            .unwrap();
        let mut control_socket = std::net::TcpStream::connect(addr).unwrap();
        control_socket
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        control_socket.set_nodelay(true).unwrap();
        let h = Header {
            tcp: false,
            ..control(42, 2)
        };
        control_socket.write_all(&h.encode()).unwrap();
        control_worker.accept_connections().unwrap();
        let token = control_worker.peers.tokens()[0];
        let mut peer = control_worker.peers.remove(token).unwrap();
        assert!(control_worker
            .service_tcp(token, &mut peer)
            .unwrap()
            .is_ok());
        let mut ack = [0; wire::HEADER];
        control_socket.read_exact(&mut ack).unwrap();
        assert_eq!(wire::parse(&ack).unwrap().seq, h.seq);
        let run = shared.lookup(42).unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = udp.local_addr().unwrap();
        let open = Header {
            kind: wire::OPEN,
            flow: 5,
            seq: 0,
            stamp: 0,
            ..h
        };
        data_worker.udp_packet(addr, &open.encode()).unwrap();
        // Duplicate OPEN on the actual endpoint does not consume another slot.
        data_worker.udp_packet(addr, &open.encode()).unwrap();
        assert_eq!(run.counts.snapshot()[ACTIVE], 1);
        let retirement = Header {
            kind: wire::CLOSE,
            flow: 0,
            seq: 1,
            len: wire::HEADER + 16,
            ..h
        };
        let mut batch = retirement.encode();
        batch[wire::HEADER..wire::HEADER + 8].copy_from_slice(&5u64.to_be_bytes());
        batch[wire::HEADER + 8..].copy_from_slice(&999u64.to_be_bytes());
        for seq in 1u64..=2 {
            batch[28..36].copy_from_slice(&seq.to_be_bytes());
            if seq == 1 {
                let mut pipelined = batch.clone();
                let mut second = batch.clone();
                second[28..36].copy_from_slice(&2u64.to_be_bytes());
                pipelined.extend_from_slice(&second);
                control_socket.write_all(&pipelined).unwrap();
            }
            peer.readable = true;
            assert!(control_worker
                .service_tcp(token, &mut peer)
                .unwrap()
                .is_ok());
            if seq == 1 {
                assert!(peer.final_report.is_some());
                assert!(peer.output.is_empty());
                assert_eq!(run.retiring.load(Ordering::Acquire), 1);
                assert_eq!(shared.retirements[1].lock().unwrap().len(), 1);
                data_worker.maintenance().unwrap();
                assert_eq!(run.retiring.load(Ordering::Acquire), 0);
                assert!(control_worker
                    .service_tcp(token, &mut peer)
                    .unwrap()
                    .is_ok());
            }
            let mut reply = [0; wire::REPORT_LEN];
            control_socket.read_exact(&mut reply).unwrap();
            let header = wire::parse(&reply).unwrap();
            assert_eq!(header.kind, wire::STATS);
            assert_eq!(header.seq, seq);
            assert_eq!(wire::counters(&reply).unwrap()[ACTIVE], 0);
        }
        assert!(shared.retirements[0].lock().unwrap().is_empty());
        assert!(shared.retirements[1].lock().unwrap().is_empty());
        data_worker.maintenance().unwrap();
        assert!(data_worker.datagrams.is_empty());
        assert!(shared.retirements[1].lock().unwrap().is_empty());
        assert_eq!(data_worker.budget.used, 0);
        assert_eq!(run.counts.snapshot()[ACTIVE], 0);
        let close = Header {
            kind: wire::CLOSE,
            ..open
        };
        data_worker.udp_packet(addr, &close.encode()).unwrap();
        assert_eq!(run.counts.snapshot()[INVALID], 0);
        data_worker.udp_packet(addr, &open.encode()).unwrap();
        assert!(data_worker.datagrams.is_empty());
        assert_eq!(run.counts.snapshot()[INVALID], 1);
        let replacement = Header { flow: 6, ..open };
        data_worker.udp_packet(addr, &replacement.encode()).unwrap();
        assert_eq!(run.counts.snapshot()[ACTIVE], 1);
        control_worker.drop_tcp(token, peer, Kind::Closed);
        data_worker.maintenance().unwrap();
        assert_eq!(shared.active.load(Ordering::Relaxed), 0);
        assert!(data_worker.datagrams.is_empty());
        control_worker.finish().unwrap();
        data_worker.finish().unwrap();
        for file in std::fs::read_dir(&o.output).unwrap() {
            let bytes = std::fs::read(file.unwrap().path()).unwrap();
            assert_eq!(bytes[bytes.len() - 4], 255, "missing recording footer");
        }
        std::fs::remove_dir_all(&o.output).unwrap();
    }

    #[test]
    fn retirement_batch_validation_and_queue_capacity() {
        let shared = Shared::new(2);
        let run = shared
            .accept(Header {
                tcp: false,
                ..control(42, 2)
            })
            .ok()
            .unwrap();
        for bytes in [Vec::new(), vec![0; 7], vec![0; RETIRE_BATCH * 8 + 8]] {
            assert!(matches!(
                shared.retire_batch(&run, &bytes),
                Err(Kind::Invalid)
            ));
        }
        let unknown = MAX_RETIREMENTS as u64 + 100;
        assert!(shared.retire_batch(&run, &unknown.to_be_bytes()).is_ok());
        assert!(shared.retirements[0].lock().unwrap().is_empty());
        assert_eq!(shared.admit(&run, unknown, 1), Err(Kind::Invalid));
        let capacity = MAX_RETIREMENTS as u64;
        for id in 1u64..=capacity {
            assert!(shared.admit(&run, id, 1).is_ok());
            assert!(shared.retire_batch(&run, &id.to_be_bytes()).is_ok());
            shared.release(&run, id);
        }
        assert!(shared.admit(&run, capacity + 1, 1).is_ok());
        assert!(matches!(
            shared.retire_batch(&run, &(capacity + 1).to_be_bytes()),
            Err(Kind::Limited)
        ));
        assert_eq!(
            shared.retirements[1].lock().unwrap().len(),
            capacity as usize
        );
    }

    #[test]
    fn retired_control_backlog_reserves_headroom_for_live_controls() {
        let shared = Shared::new(1);
        let threshold = MAX_RETIREMENTS - MAX_RUNS * RETIRE_BATCH;
        shared
            .queued_retirements
            .store(threshold, Ordering::Release);
        assert!(matches!(shared.accept(control(42, 1)), Err(Kind::Limited)));
        assert_eq!(shared.controls.load(Ordering::Relaxed), 0);
        shared
            .queued_retirements
            .store(threshold - 1, Ordering::Release);
        assert!(shared.accept(control(42, 1)).is_ok());
    }

    #[test]
    fn buffered_input_timeout_excludes_owner_waits() {
        let start = Instant::now();
        let mut input = Input {
            since: Some(start),
            batch_since: Some(start),
            ..Input::default()
        };
        input.resume_after_pause(
            start + Duration::from_millis(1),
            start + Duration::from_millis(81),
        );
        input.resume_after_pause(
            start + Duration::from_millis(82),
            start + Duration::from_millis(162),
        );
        assert_eq!(input.since, Some(start + Duration::from_millis(160)));
        assert_eq!(input.batch_since, input.since);
    }

    #[test]
    fn partial_writes_preserve_bytes_and_release_budget() {
        let o = test_config("writes");
        let shared = Arc::new(Shared::new(2));
        let mut worker =
            Worker::new(&o, 0, shared.clone(), Arc::new(AtomicBool::new(false))).unwrap();
        let (tx, rx) = std::os::unix::net::UnixStream::pair().unwrap();
        tx.set_nonblocking(true).unwrap();
        rx.set_nonblocking(true).unwrap();
        let tx: Socket = tx.into();
        let rx: Socket = rx.into();
        tx.set_send_buffer_size(4096).unwrap();
        let mut peer = pending(tx);
        assert!(reserve(&shared.pending, MAX_PENDING));
        let h = Header {
            kind: wire::DATA,
            len: wire::MAX,
            ..control(1, 1)
        };
        let mut frame = h.encode();
        for (i, byte) in frame[wire::HEADER..].iter_mut().enumerate() {
            *byte = (i % 251) as u8;
        }
        for _ in 0..4 {
            assert!(worker.budget.take(frame.len()));
            peer.queued += frame.len();
            peer.output.push_back(Output::new(frame.clone(), h, None));
        }
        assert!(peer.queued <= PEER_BYTES);
        assert!(worker.flush_tcp(&mut peer).is_ok());
        assert!(peer.output.is_empty() || peer.output.front().unwrap().offset > 0);
        let mut received = Vec::new();
        let mut buf = [0; 16384];
        let deadline = Instant::now() + Duration::from_secs(2);
        while received.len() < frame.len() * 4 {
            assert!(Instant::now() < deadline);
            loop {
                match net::recv(&rx, &mut buf) {
                    Ok(0) => panic!("unexpected EOF"),
                    Ok(n) => received.extend_from_slice(&buf[..n]),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => panic!("receive: {e}"),
                }
            }
            peer.writable = true;
            assert!(worker.flush_tcp(&mut peer).is_ok());
        }
        assert_eq!(received, frame.repeat(4));
        assert!(peer.output.is_empty());
        assert_eq!(worker.budget.used, 0);
        worker.drop_tcp(Token(2), peer, Kind::Closed);
        worker.finish().unwrap();
        std::fs::remove_dir_all(&o.output).unwrap();
    }

    #[test]
    fn input_batches_frames_across_service_quanta_without_extra_receives() {
        let mut stream = Vec::new();
        let frames: Vec<_> = (0..QUANTUM + 3)
            .map(|seq| {
                let mut frame = Header {
                    kind: wire::DATA,
                    len: 128,
                    seq: seq as u64,
                    ..control(3, 1)
                }
                .encode();
                frame[wire::HEADER..].fill(seq as u8);
                stream.extend_from_slice(&frame);
                frame
            })
            .collect();
        let mut remaining = stream.as_slice();
        let mut calls = 0;
        let mut input = Input::default();
        let mut budget = Budget::default();
        let mut buffers = BufferPool::default();
        for expected in frames {
            let step = input
                .read_with(&mut budget, &mut buffers, 0, 128, |output| {
                    calls += 1;
                    let n = output.len().min(remaining.len());
                    output[..n].copy_from_slice(&remaining[..n]);
                    remaining = &remaining[n..];
                    Ok(n)
                })
                .unwrap();
            let ReadStep::Frame(frame) = step else {
                panic!("a buffered complete frame must be delivered in one step");
            };
            assert_eq!(frame, expected);
            assert_eq!(budget.used, frame.len());
            budget.give(frame.len());
            buffers.give(frame);
        }
        assert_eq!(calls, stream.len().div_ceil(INPUT_BATCH_BYTES));
        assert!(input.since.is_none());
        assert_eq!(budget.used, 0);
        assert!(matches!(
            input.read_with(&mut budget, &mut buffers, 0, 128, |_| Ok(0)),
            Ok(ReadStep::Eof)
        ));
    }

    #[test]
    fn input_mixed_frames_cross_batch_boundaries_without_losing_bytes() {
        let frames: Vec<_> = (0..80)
            .map(|seq| {
                let mut frame = Header {
                    kind: wire::DATA,
                    len: [wire::HEADER, 77, 129, INPUT_BATCH_BYTES + 9][seq % 4],
                    seq: seq as u64,
                    ..control(3, 1)
                }
                .encode();
                frame[wire::HEADER..].fill(seq as u8);
                frame
            })
            .collect();
        let stream = frames.concat();
        let mut remaining = stream.as_slice();
        let mut input = Input::default();
        let mut budget = Budget::default();
        let mut buffers = BufferPool::default();
        let mut delivered = 0;
        for _ in 0..frames.len() * 4 {
            let started = input.since;
            let step = input
                .read_with(&mut budget, &mut buffers, 0, wire::MAX, |output| {
                    let n = remaining.len().min(output.len());
                    output[..n].copy_from_slice(&remaining[..n]);
                    remaining = &remaining[n..];
                    Ok(n)
                })
                .unwrap();
            match step {
                ReadStep::Frame(frame) => {
                    assert_eq!(frame, frames[delivered]);
                    assert_eq!(budget.used, frame.len());
                    budget.give(frame.len());
                    buffers.give(frame);
                    delivered += 1;
                    if delivered == frames.len() {
                        break;
                    }
                }
                ReadStep::Progress => {
                    assert_eq!(budget.used, input.frame.len());
                    assert!(input.since.is_some());
                    if started.is_some() {
                        assert_eq!(input.since, started);
                    }
                }
                _ => panic!("unexpected read result with queued frames"),
            }
        }
        assert_eq!(delivered, frames.len());
        assert!(remaining.is_empty());
        assert!(input.since.is_none());
        assert_eq!(budget.used, 0);
    }

    #[test]
    fn input_read_ahead_preserves_partial_deadlines_and_eof() {
        let frame = Header {
            len: 128,
            ..control(3, 1)
        }
        .encode();
        let mut input = Input::default();
        let mut budget = Budget::default();
        let mut buffers = BufferPool::default();
        let step = input
            .read_with(&mut budget, &mut buffers, 0, 128, |output| {
                output[..128].copy_from_slice(&frame);
                output[128..131].copy_from_slice(&frame[..3]);
                Ok(131)
            })
            .unwrap();
        assert!(matches!(step, ReadStep::Frame(_)));
        budget.give(128);
        // The next frame's timer starts at receipt, before its prefix is parsed.
        let started = input.since.unwrap();
        assert_eq!(input.batch_since, Some(started));
        assert!(matches!(
            input.read_with(&mut budget, &mut buffers, 0, 128, |_| {
                panic!("buffered prefix must not receive")
            }),
            Ok(ReadStep::Progress)
        ));
        for error in [io::ErrorKind::Interrupted, io::ErrorKind::WouldBlock] {
            let step = input.read_with(&mut budget, &mut buffers, 0, 128, |_| Err(error.into()));
            assert!(matches!(step, Ok(ReadStep::Progress | ReadStep::Blocked)));
            assert_eq!(input.since, Some(started));
        }
        assert!(matches!(
            input.read_with(&mut budget, &mut buffers, 0, 128, |output| {
                output[..17].copy_from_slice(&frame[3..20]);
                Ok(17)
            }),
            Ok(ReadStep::Progress)
        ));
        assert_eq!(input.since, Some(started));
        assert_eq!(budget.used, 128);
        assert!(matches!(
            input.read_with(&mut budget, &mut buffers, 0, 128, |_| Ok(0)),
            Err(Kind::Failed)
        ));
        budget.give(input.frame.len());
        assert_eq!(budget.used, 0);
    }

    #[test]
    fn input_buffered_frames_use_current_role_and_budget_limits() {
        let first = control(3, 1).encode();
        let second = Header {
            len: 128,
            ..control(3, 1)
        }
        .encode();
        for (max_frame, queued, used, error) in [
            (wire::HEADER, 0, 0, Some(Kind::Invalid)),
            (128, PEER_BYTES - 127, 0, Some(Kind::Limited)),
            (128, 0, WORKER_BYTES - 127, Some(Kind::Limited)),
            (128, PEER_BYTES - 128, WORKER_BYTES - 128, None),
        ] {
            let mut input = Input::default();
            let mut budget = Budget::default();
            let mut buffers = BufferPool::default();
            assert!(matches!(
                input.read_with(&mut budget, &mut buffers, 0, wire::HEADER, |output| {
                    output[..first.len()].copy_from_slice(&first);
                    output[first.len()..first.len() + second.len()].copy_from_slice(&second);
                    Ok(first.len() + second.len())
                }),
                Ok(ReadStep::Frame(_))
            ));
            budget.give(first.len());
            budget.used = used;
            let step = input.read_with(&mut budget, &mut buffers, queued, max_frame, |_| {
                panic!("second frame already buffered")
            });
            if let Some(error) = error {
                assert!(matches!(step, Err(kind) if kind == error));
                assert!(input.frame.is_empty());
                assert_eq!(budget.used, used);
            } else {
                assert!(matches!(step, Ok(ReadStep::Frame(frame)) if frame == second));
                assert_eq!(budget.used, WORKER_BYTES);
            }
        }
    }

    #[test]
    fn input_valid_prefix_precedes_invalid_read_ahead_without_allocation() {
        for (magic, invalid_len) in [
            (b"FLWG", 0),
            (b"FLWG", wire::HEADER - 1),
            (b"FLWG", wire::MAX + 1),
            (b"FAIL", wire::HEADER),
        ] {
            let first = control(3, 1).encode();
            let mut input = Input::default();
            let mut budget = Budget::default();
            let mut buffers = BufferPool::default();
            assert!(matches!(
                input.read_with(&mut budget, &mut buffers, 0, wire::MAX, |output| {
                    output[..first.len()].copy_from_slice(&first);
                    output[first.len()..first.len() + 4].copy_from_slice(magic);
                    output[first.len() + 4..first.len() + 8]
                        .copy_from_slice(&(invalid_len as u32).to_be_bytes());
                    Ok(first.len() + 8)
                }),
                Ok(ReadStep::Frame(_))
            ));
            budget.give(first.len());
            assert!(matches!(
                input.read_with(&mut budget, &mut buffers, 0, wire::MAX, |_| {
                    panic!("invalid prefix already buffered")
                }),
                Err(Kind::Invalid)
            ));
            assert_eq!(budget.used, 0);
            assert_eq!(input.frame.capacity(), 0);
        }
    }

    #[test]
    fn input_large_frames_receive_directly_after_bounded_read_ahead() {
        let mut expected = Header {
            len: wire::MAX,
            ..control(3, 1)
        }
        .encode();
        expected[wire::HEADER..].fill(0x5a);
        let mut input = Input::default();
        let mut budget = Budget::default();
        let mut buffers = BufferPool::default();
        buffers.give(vec![0xa5; wire::MAX]);
        assert!(matches!(
            input.read_with(&mut budget, &mut buffers, 0, wire::MAX, |output| {
                assert_eq!(output.len(), INPUT_BATCH_BYTES);
                output.copy_from_slice(&expected[..INPUT_BATCH_BYTES]);
                Ok(output.len())
            }),
            Ok(ReadStep::Progress)
        ));
        let started = input.since;
        assert_eq!(budget.used, wire::MAX);
        let step = input
            .read_with(&mut budget, &mut buffers, 0, wire::MAX, |output| {
                assert_eq!(output.len(), wire::MAX - INPUT_BATCH_BYTES);
                output.copy_from_slice(&expected[INPUT_BATCH_BYTES..]);
                Ok(output.len())
            })
            .unwrap();
        assert!(matches!(step, ReadStep::Frame(frame) if frame == expected));
        assert!(started.is_some());
        assert!(input.since.is_none());
        budget.give(wire::MAX);
        assert_eq!(budget.used, 0);
    }

    #[test]
    fn incremental_reads_keep_partial_frames_and_bound_allocations() {
        use std::io::Write;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut tx = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        tx.set_nodelay(true).unwrap();
        let (rx, _) = listener.accept().unwrap();
        rx.set_nonblocking(true).unwrap();
        let rx: Socket = rx.into();
        let frame = Header {
            kind: wire::DATA,
            len: 128,
            ..control(3, 1)
        }
        .encode();
        let mut input = Input::default();
        let mut budget = Budget::default();
        let mut buffers = BufferPool::default();
        buffers.give(vec![0xA5; frame.len()]);
        for (n, byte) in frame.iter().enumerate() {
            tx.write_all(&[*byte]).unwrap();
            loop {
                match input
                    .read(&rx, &mut budget, &mut buffers, 0, wire::MAX)
                    .ok()
                    .unwrap()
                {
                    ReadStep::Progress => continue,
                    ReadStep::Blocked => break,
                    ReadStep::Frame(got) => {
                        assert_eq!(n, frame.len() - 1);
                        assert_eq!(got, frame);
                        budget.give(got.len());
                        break;
                    }
                    ReadStep::Eof => panic!("unexpected EOF"),
                }
            }
        }
        assert_eq!(budget.used, 0);
        tx.write_all(&frame[..8]).unwrap();
        assert!(matches!(
            input.read(&rx, &mut budget, &mut buffers, PEER_BYTES, wire::MAX),
            Err(Kind::Limited)
        ));
        assert_eq!(budget.used, 0);
    }
}
