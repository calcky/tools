//! Real CLI/protocol tests; no privileged ports, namespaces, or network tuning.
#![cfg(target_os = "linux")]

use socket2::{Domain, Socket, Type};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const BIN: &str = env!("CARGO_BIN_EXE_flowgen");
const LIMIT: Duration = Duration::from_secs(10);
const TICK: Duration = Duration::from_millis(10);

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("flowgen-test-{}-{stamp}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        if thread::panicking() {
            eprintln!("flowgen test artifacts retained: {}", self.0.display());
        } else {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

// Serialize separate cargo invocations too. Never unlink a flock file: another
// process may already be waiting on that inode. Closing releases the lock.
fn suite_lock() -> File {
    let path = std::env::temp_dir().join(format!("flowgen-loopback-{}.lock", unsafe {
        libc::geteuid()
    }));
    let file = File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .unwrap();
    let start = Instant::now();
    loop {
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return file;
        }
        let error = io::Error::last_os_error();
        assert_eq!(
            error.kind(),
            io::ErrorKind::WouldBlock,
            "suite lock: {error}"
        );
        assert!(
            start.elapsed() < Duration::from_secs(60),
            "another integration suite held its lock for 60s"
        );
        thread::sleep(TICK);
    }
}

struct Process {
    child: Child,
    out: PathBuf,
    err: PathBuf,
}
struct ResultOutput {
    status: ExitStatus,
    out: String,
    err: String,
}
impl ResultOutput {
    fn success(&self) {
        assert!(
            self.status.success(),
            "exit {}\nstdout:\n{}\nstderr:\n{}",
            self.status,
            self.out,
            self.err
        );
        assert!(
            self.err.trim().is_empty(),
            "unexpected stderr: {}",
            self.err
        );
    }
}
impl Process {
    fn spawn(root: &Scratch, name: &str, args: &[String]) -> Self {
        Self::spawn_with_file_limit(root, name, args, None)
    }
    fn spawn_with_file_limit(
        root: &Scratch,
        name: &str,
        args: &[String],
        soft_limit: Option<libc::rlim_t>,
    ) -> Self {
        let out = root.path(&format!("{name}.stdout"));
        let err = root.path(&format!("{name}.stderr"));
        let mut command = Command::new(BIN);
        if let Some(soft_limit) = soft_limit {
            // Only async-signal-safe calls in the forked child before exec.
            unsafe {
                command.pre_exec(move || {
                    let mut limit = libc::rlimit {
                        rlim_cur: 0,
                        rlim_max: 0,
                    };
                    if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    limit.rlim_cur = soft_limit;
                    if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        let child = command
            .args(args)
            .stdin(Stdio::null())
            .stdout(File::create(&out).unwrap())
            .stderr(File::create(&err).unwrap())
            .spawn()
            .unwrap();
        Self { child, out, err }
    }
    fn output(&self) -> String {
        fs::read_to_string(&self.out).unwrap()
    }
    fn errors(&self) -> String {
        fs::read_to_string(&self.err).unwrap()
    }
    fn wait_for(&mut self, predicate: impl Fn(&str) -> bool) {
        let start = Instant::now();
        loop {
            let out = self.output();
            if predicate(&out) {
                return;
            }
            assert!(
                self.child.try_wait().unwrap().is_none(),
                "process exited before readiness:\n{out}\n{}",
                self.errors()
            );
            assert!(
                start.elapsed() < LIMIT,
                "readiness timeout:\n{out}\n{}",
                self.errors()
            );
            thread::sleep(TICK);
        }
    }
    fn finish(&mut self) -> ResultOutput {
        let start = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return ResultOutput {
                    status,
                    out: self.output(),
                    err: self.errors(),
                };
            }
            assert!(
                start.elapsed() < LIMIT,
                "child exceeded {LIMIT:?}:\n{}\n{}",
                self.output(),
                self.errors()
            );
            thread::sleep(TICK);
        }
    }
    fn interrupt(&self) {
        assert_eq!(
            unsafe { libc::kill(self.child.id() as libc::pid_t, libc::SIGINT) },
            0,
            "SIGINT failed"
        );
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

struct Reservation {
    tcp: TcpListener,
    _udp: UdpSocket,
}
impl Reservation {
    fn bind(ip: IpAddr, port: u16) -> io::Result<Self> {
        let tcp = TcpListener::bind(SocketAddr::new(ip, port))?;
        let udp = UdpSocket::bind(tcp.local_addr()?)?;
        Ok(Self { tcp, _udp: udp })
    }
    fn address(&self) -> SocketAddr {
        self.tcp.local_addr().unwrap()
    }
}

// Reserve each whole source block before handing it to the client. Blocks are
// distinct within the suite, and chosen outside Linux's ephemeral port range.
struct Sources {
    used: HashSet<u16>,
    ephemeral: (u16, u16),
    reserved: Vec<(u16, u16)>,
}
impl Sources {
    fn new() -> Self {
        let range = fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range").unwrap();
        let ports: Vec<u16> = range
            .split_whitespace()
            .map(|s| s.parse().unwrap())
            .collect();
        let reserved = fs::read_to_string("/proc/sys/net/ipv4/ip_local_reserved_ports")
            .unwrap()
            .trim()
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| {
                let (a, b) = s.split_once('-').unwrap_or((s, s));
                (a.parse().unwrap(), b.parse().unwrap())
            })
            .collect();
        Self {
            used: HashSet::new(),
            ephemeral: (ports[0], ports[1]),
            reserved,
        }
    }
    fn take(&mut self, ip: IpAddr) -> (String, Vec<Reservation>) {
        for low in (10000u16..65000).step_by(64) {
            let high = low + 63;
            if self.used.contains(&low)
                || (low <= self.ephemeral.1 && high >= self.ephemeral.0)
                || self.reserved.iter().any(|&(a, b)| low <= b && high >= a)
            {
                continue;
            }
            let sockets: io::Result<Vec<_>> = (low..=high)
                .map(|port| Reservation::bind(ip, port))
                .collect();
            if let Ok(sockets) = sockets {
                self.used.insert(low);
                return (format!("{low}-{high}"), sockets);
            }
        }
        panic!("no unoccupied 64-port source block outside the ephemeral/reserved ranges");
    }
}

fn strings(args: &[&str]) -> Vec<String> {
    args.iter().map(|s| (*s).to_owned()).collect()
}
fn start_server(root: &Scratch, ipv6: bool) -> (Process, SocketAddr) {
    start_server_recording(root, ipv6, "events", 1)
}

fn start_server_recording(
    root: &Scratch,
    ipv6: bool,
    mode: &str,
    workers: usize,
) -> (Process, SocketAddr) {
    let any = if ipv6 { "::" } else { "0.0.0.0" }.parse().unwrap();
    for attempt in 0..8 {
        let reservation = Reservation::bind(any, 0).unwrap();
        let port = reservation.address().port();
        let name = format!(
            "server-{}-{mode}-{workers}-{attempt}",
            if ipv6 { "v6" } else { "v4" }
        );
        let mut args = strings(&[
            "-s",
            "-w",
            &workers.to_string(),
            "-L",
            mode,
            "-p",
            &port.to_string(),
            if ipv6 { "-6" } else { "-4" },
            "-o",
        ]);
        args.push(root.path(&name).display().to_string());
        drop(reservation);
        let mut server = Process::spawn(root, &name, &args);
        let start = Instant::now();
        loop {
            let out = server.output();
            let announced = out.lines().any(|line| {
                let line = line.to_ascii_lowercase();
                line.contains(&port.to_string())
                    && (line.contains("server") || line.contains("listen"))
            });
            let address = SocketAddr::new(
                if ipv6 { "::1" } else { "127.0.0.1" }.parse().unwrap(),
                port,
            );
            if announced && TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_ok()
            {
                return (server, address);
            }
            if server.child.try_wait().unwrap().is_some() {
                let err = server.errors();
                // A foreign process can claim the port between release and exec.
                if err.contains("Address already in use") || err.contains("os error 98") {
                    break;
                }
                panic!("server startup failed:\n{out}\n{err}");
            }
            assert!(
                start.elapsed() < LIMIT,
                "server startup timeout:\n{out}\n{}",
                server.errors()
            );
            thread::sleep(TICK);
        }
    }
    panic!("server port was claimed during all startup attempts");
}

fn client_args(
    root: &Scratch,
    name: &str,
    address: SocketAddr,
    tcp: bool,
    range: &str,
    churn: bool,
    duration: &str,
) -> Vec<String> {
    let mut args = strings(&[
        if tcp { "-t" } else { "-u" },
        if address.is_ipv6() { "-6" } else { "-4" },
        "-p",
        &address.port().to_string(),
        "-c",
        "3",
        "-a",
        "0.3",
        "-w",
        "1",
        "-T",
        duration,
        "-r",
        "20",
        "-W",
        "0.3",
        "-U",
        if churn { "5" } else { "0" },
        "-P",
        range,
        "-B",
        &address.ip().to_string(),
        "-o",
    ]);
    args.push(root.path(name).display().to_string());
    args.push(address.ip().to_string());
    args
}

fn counter(out: &str, name: &str) -> u64 {
    let line = out
        .lines()
        .find(|s| s.contains("Finished |"))
        .expect("missing final counters");
    let fields: Vec<_> = line.split_whitespace().collect();
    let i = fields
        .iter()
        .position(|&s| s == name)
        .unwrap_or_else(|| panic!("missing {name}: {line}"));
    fields[i + 1].parse().unwrap()
}
fn healthy(result: &ResultOutput) {
    result.success();
    assert!(
        result.out.contains("LOAD | warmup complete"),
        "{}",
        result.out
    );
    assert!(
        result.out.contains("RTT"),
        "missing RTT analysis: {}",
        result.out
    );
    let sent = counter(&result.out, "sent");
    assert!(sent >= 6, "too few requests: {}", result.out);
    assert_eq!(counter(&result.out, "received"), sent, "{}", result.out);
    for name in ["timeout", "canceled", "late"] {
        assert_eq!(counter(&result.out, name), 0, "{name}: {}", result.out);
    }
}

fn recording_events(dir: &Path) -> Vec<[u8; 40]> {
    let bytes = fs::read(dir.join("client-0.fgr")).unwrap();
    assert_eq!(&bytes[..8], b"FGRLOG\r\n");
    assert_eq!((bytes.len() - 32) % 40, 0, "partial raw event");
    let mut events = bytes[32..].as_chunks::<40>().0.to_vec();
    let footer = events.pop().unwrap();
    assert_eq!(footer[36], 255, "missing recorder footer");
    assert_eq!(
        u64::from_le_bytes(footer[8..16].try_into().unwrap()),
        0,
        "recorder dropped events"
    );
    events
}

fn inspect_recording(dir: &Path, extra_allocations: bool) {
    let tuples = fs::read_to_string(dir.join("tuples-0.csv")).unwrap();
    let rows: Vec<_> = tuples.lines().skip(1).collect();
    if extra_allocations {
        assert!(
            rows.len() > 3,
            "missing replacement allocations in {tuples}"
        );
    } else {
        assert_eq!(rows.len(), 3, "unexpected replacement in fixed run");
    }
    let endpoints: HashSet<_> = rows
        .iter()
        .map(|row| {
            let fields: Vec<_> = row.split(',').collect();
            (fields[1], fields[2])
        })
        .collect();
    assert_eq!(endpoints.len(), rows.len(), "source tuple reused");
    let events = recording_events(dir);
    let mut ready = HashSet::new();
    let mut sends = 0;
    for event in &events {
        let flow = u64::from_le_bytes(event[..8].try_into().unwrap());
        if event[36] == 1 {
            ready.insert(flow);
        }
        if event[36] == 2 {
            assert!(
                ready.len() >= 3,
                "data scheduled before warmup readiness barrier"
            );
            sends += 1;
        }
        if event[36] == 2 || event[36] == 3 {
            assert_eq!(
                u32::from_le_bytes(event[32..36].try_into().unwrap()),
                128,
                "unequal application message length"
            );
        }
    }
    assert!(sends > 0);
    assert!(
        dir.join("server-final.txt").is_file(),
        "missing final server report"
    );
}

fn occupied_warmup(
    root: &Scratch,
    sources: &mut Sources,
    address: SocketAddr,
    tcp: bool,
    persistent: bool,
) {
    let name = format!(
        "occupied-{}-{}-{}",
        if address.is_ipv6() { "v6" } else { "v4" },
        if tcp { "tcp" } else { "udp" },
        if persistent {
            "persistent"
        } else {
            "transient"
        }
    );
    eprintln!("case: {name}");
    let (range, mut occupied) = sources.take(address.ip());
    if !persistent {
        occupied.truncate(2);
    }
    let args = client_args(root, &name, address, tcp, &range, false, "0.4");
    let started = Instant::now();
    let mut client = Process::spawn(root, &name, &args);
    if !persistent {
        // Keep the first two tuples occupied through warmup. Release only at
        // the barrier, so success must use fresh tuples in the bounded grace.
        client.wait_for(|out| out.contains("LOAD | warmup complete"));
        drop(occupied);
    }
    let result = client.finish();
    let events = recording_events(&root.path(&name));
    let failures = events.iter().filter(|e| e[36] == 7).count();
    let diagnostics: Vec<_> = events.iter().filter(|e| e[36] == 17).collect();
    assert_eq!(diagnostics.len(), failures);
    for event in diagnostics {
        let value = u64::from_le_bytes(event[24..32].try_into().unwrap());
        assert_eq!(value >> 32, 2, "occupied source must report bind stage");
        assert_eq!(value as u32 as i32, libc::EADDRINUSE);
    }
    let opened: Vec<_> = events
        .iter()
        .filter(|e| e[36] == 0)
        .map(|e| u64::from_le_bytes(e[16..24].try_into().unwrap()))
        .collect();
    // N/t is 10 attempts/s. At most six slots fit before t + W = 0.6s.
    assert!(
        !opened.is_empty() && opened.len() <= 6,
        "unbounded retries: {opened:?}"
    );
    assert!(
        *opened.last().unwrap() < 650_000_000,
        "admissions exceeded grace: {opened:?}"
    );
    for pair in opened.windows(2) {
        // A delayed attempt near a slot boundary may legitimately be close
        // to the next attempt; catching up twice within one slot is forbidden.
        assert!(
            pair[1] / 100_000_000 > pair[0] / 100_000_000,
            "warmup catch-up burst: {opened:?}"
        );
    }
    if persistent {
        assert!(
            !result.status.success(),
            "occupied pool unexpectedly reached LOAD"
        );
        assert!(result.err.contains("WARMUP FAILED"), "{}", result.err);
        assert!(!result.out.contains("LOAD |"), "{}", result.out);
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "warmup did not stop within its bounded grace"
        );
        assert_eq!(counter(&result.out, "sent"), 0);
        assert_eq!(counter(&result.out, "received"), 0);
        assert!(
            events.iter().all(|e| !matches!(e[36], 1..=3)),
            "data or readiness recorded despite all ports being occupied"
        );
        assert_eq!(events.iter().filter(|e| e[36] == 7).count(), opened.len());
    } else {
        healthy(&result);
        assert_eq!(
            opened.len(),
            5,
            "two failed tuples plus three ready sessions"
        );
        assert!(
            *opened.last().unwrap() >= 400_000_000,
            "did not exercise warmup grace"
        );
        assert_eq!(events.iter().filter(|e| e[36] == 7).count(), 2);
        assert_eq!(events.iter().filter(|e| e[36] == 1).count(), 3);
        for event in events.iter().filter(|e| e[36] == 1) {
            assert!(
                u64::from_le_bytes(event[..8].try_into().unwrap()) > 2,
                "failed tuple was reused"
            );
        }
        inspect_recording(&root.path(&name), true);
    }
    offline(root, &name);
}

fn single_tuple_reuse(root: &Scratch, sources: &mut Sources, address: SocketAddr) {
    let name = if address.is_ipv6() {
        "reuse-one-v6"
    } else {
        "reuse-one-v4"
    };
    eprintln!("case: {name} (one session/port, four requested workers, 50ms cooldown)");
    let (range, reservation) = sources.take(address.ip());
    let port = range.split('-').next().unwrap();
    let mut args = client_args(
        root,
        name,
        address,
        false,
        &format!("{port}-{port}"),
        true,
        "1.2",
    );
    for (option, value) in [("-c", "1"), ("-w", "4")] {
        let index = args.iter().position(|arg| arg == option).unwrap();
        args[index + 1] = value.to_owned();
    }
    args.extend(strings(&["-Q", "0.05"]));
    drop(reservation);
    let result = Process::spawn(root, name, &args).finish();
    healthy(&result);
    let dir = root.path(name);
    let metadata = fs::read_to_string(dir.join("run.txt")).unwrap();
    assert!(
        metadata.lines().any(|line| line == "workers 1"),
        "workers were not clamped to sessions: {metadata}"
    );
    let recordings: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .filter(|name| {
            name.to_string_lossy().starts_with("client-")
                && name.to_string_lossy().ends_with(".fgr")
        })
        .collect();
    assert_eq!(
        recordings,
        ["client-0.fgr"],
        "unexpected zero-session workers"
    );

    let tuples = fs::read_to_string(dir.join("tuples-0.csv")).unwrap();
    let mut generations = HashSet::new();
    for row in tuples.lines().skip(1) {
        let fields: Vec<_> = row.split(',').collect();
        assert_eq!(fields.len(), 6);
        assert!(
            generations.insert(fields[0].parse::<u64>().unwrap()),
            "generation reused: {row}"
        );
        assert_eq!(fields[1], address.ip().to_string());
        assert_eq!(fields[2], port, "client escaped its single-port pool");
        assert_eq!(fields[3], address.ip().to_string());
        assert_eq!(fields[4], address.port().to_string());
        assert_eq!(fields[5], "udp");
    }

    let mut live = None;
    let mut last_close = None;
    let mut ready = HashSet::new();
    let mut reused = 0;
    for event in recording_events(&dir) {
        let flow = u64::from_le_bytes(event[..8].try_into().unwrap());
        let time = u64::from_le_bytes(event[16..24].try_into().unwrap());
        match event[36] {
            0 => {
                assert!(
                    live.replace(flow).is_none(),
                    "overlapping generations on one tuple"
                );
                assert!(generations.contains(&flow));
                if let Some(closed_at) = last_close {
                    assert!(
                        time >= closed_at + 50_000_000,
                        "tuple reused before cooldown: closed={closed_at}, opened={time}"
                    );
                    reused += 1;
                }
            }
            1 => {
                assert_eq!(live, Some(flow));
                assert!(ready.insert(flow), "duplicate readiness for one generation");
            }
            2 | 3 => {
                assert_eq!(live, Some(flow));
                assert!(ready.contains(&flow), "data before generation became ready");
            }
            6 => {
                assert_eq!(live.take(), Some(flow));
                last_close = Some(time);
            }
            7 => panic!("single-tuple churn encountered a setup/stream failure"),
            _ => {}
        }
    }
    assert!(live.is_none(), "final generation was not closed");
    assert!(
        ready.len() >= 3 && reused >= 2,
        "reusable pool stalled: ready={}, reuses={reused}",
        ready.len()
    );
    assert_eq!(
        ready, generations,
        "some replacement generations never became ready"
    );
    assert!(dir.join("server-final.txt").is_file());
    offline(root, name);
}

fn offline(root: &Scratch, name: &str) -> ResultOutput {
    let args = vec!["-R".to_owned(), root.path(name).display().to_string()];
    let result = Process::spawn(root, &format!("{name}-offline"), &args).finish();
    result.success();
    assert!(result.out.contains("RTT"), "{}", result.out);
    result
}

fn connect(address: SocketAddr) -> TcpStream {
    let socket = TcpStream::connect_timeout(&address, Duration::from_secs(1)).unwrap();
    socket.set_nodelay(true).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    socket
}
fn frame(kind: u8, run: u64, flow: u64, seq: u64, len: usize) -> Vec<u8> {
    let mut bytes = vec![0; len];
    bytes[..4].copy_from_slice(b"FLWG");
    bytes[4..8].copy_from_slice(&(len as u32).to_be_bytes());
    bytes[8] = kind;
    bytes[9] = 1;
    bytes[10] = 1;
    bytes[12..20].copy_from_slice(&run.to_be_bytes());
    bytes[20..28].copy_from_slice(&flow.to_be_bytes());
    bytes[28..36].copy_from_slice(&seq.to_be_bytes());
    if kind == 5 {
        bytes[36..44].copy_from_slice(&12345678u64.to_be_bytes());
    }
    if kind == 1 || kind == 3 {
        bytes[44..48].copy_from_slice(&128u32.to_be_bytes());
    }
    for (i, byte) in bytes[48..].iter_mut().enumerate() {
        *byte = (i % 251) as u8;
    }
    bytes
}
#[track_caller]
fn read_frame(socket: &mut TcpStream) -> Vec<u8> {
    let mut prefix = [0; 8];
    socket.read_exact(&mut prefix).unwrap();
    let len = u32::from_be_bytes(prefix[4..].try_into().unwrap()) as usize;
    assert!((48..=65507).contains(&len));
    let mut bytes = vec![0; len];
    bytes[..8].copy_from_slice(&prefix);
    socket.read_exact(&mut bytes[8..]).unwrap();
    bytes
}
fn expect_closed(socket: &mut TcpStream) {
    let mut byte = [0];
    match socket.read(&mut byte) {
        Ok(0) => {}
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::ConnectionAborted
            ) => {}
        other => panic!("expected malformed/incomplete stream closure, got {other:?}"),
    }
}

fn tcp_frames(address: SocketAddr) {
    let run = 0xfeed_0000_0000 | std::process::id() as u64;
    let mut control = connect(address);
    let mut registration = frame(1, run, 1, 300_000_000, 48);
    registration[36..44].copy_from_slice(&30_000_000_000u64.to_be_bytes());
    for part in registration.chunks(7) {
        control.write_all(part).unwrap();
    }
    assert_eq!(read_frame(&mut control)[8], 2, "control not accepted");
    let mut data = connect(address);
    data.write_all(&frame(3, run, 1, 0, 48)).unwrap();
    assert_eq!(read_frame(&mut data)[8], 4, "flow not acknowledged");
    let request = frame(5, run, 1, 1, 128);
    data.write_all(&request[..7]).unwrap();
    data.set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let error = data
        .read(&mut [0])
        .expect_err("server echoed an incomplete frame");
    assert!(matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    ));
    data.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    for part in request[7..].chunks(11) {
        data.write_all(part).unwrap();
    }
    assert_eq!(
        read_frame(&mut data),
        request,
        "split frame changed on echo"
    );
    let a = frame(5, run, 1, 2, 128);
    let b = frame(5, run, 1, 3, 128);
    data.write_all(&[a.clone(), b.clone()].concat()).unwrap();
    assert_eq!(read_frame(&mut data), a);
    assert_eq!(read_frame(&mut data), b);
    // The old flow is still live when its replacement registers. A client's
    // target of one must not prevent this overlap on the server.
    let mut replacement = connect(address);
    replacement.write_all(&frame(3, run, 3, 0, 48)).unwrap();
    assert_eq!(read_frame(&mut replacement)[8], 4);
    let request = frame(5, run, 3, 1, 128);
    replacement.write_all(&request).unwrap();
    assert_eq!(read_frame(&mut replacement), request);
    data.write_all(&frame(5, run, 1, 4, 128)[..61]).unwrap();
    data.shutdown(Shutdown::Write).unwrap();
    expect_closed(&mut data);
    for mutation in 0..4 {
        let mut malformed = frame(3, run, 2, 0, 48);
        match mutation {
            0 => malformed[..4].copy_from_slice(b"BAD!"),
            1 => malformed[4..8].copy_from_slice(&u32::MAX.to_be_bytes()),
            2 => malformed[4..8].copy_from_slice(&47u32.to_be_bytes()),
            _ => malformed[9] = 99,
        }
        let mut socket = connect(address);
        socket.write_all(&malformed).unwrap();
        expect_closed(&mut socket);
    }
    let mut partial = connect(address);
    partial.write_all(b"FLW").unwrap();
    partial.shutdown(Shutdown::Write).unwrap();
    expect_closed(&mut partial);
    control.write_all(&frame(8, run, 0, 1, 48)).unwrap();
    assert_eq!(
        read_frame(&mut control)[8],
        7,
        "server failed after bad streams"
    );
}

fn udp_frame(kind: u8, run: u64, flow: u64, seq: u64, len: usize) -> Vec<u8> {
    let mut bytes = frame(kind, run, flow, seq, len);
    bytes[10] = 0;
    bytes
}

fn udp_roundtrip(socket: &UdpSocket, request: &[u8]) -> Vec<u8> {
    socket.send(request).unwrap();
    let mut bytes = [0; 65536];
    let n = socket.recv(&mut bytes).unwrap();
    bytes[..n].to_vec()
}

fn udp_ignored(socket: &UdpSocket, request: &[u8]) {
    socket.send(request).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(80)))
        .unwrap();
    let error = socket
        .recv(&mut [0; 256])
        .expect_err("retired flow received a response");
    assert!(matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    ));
    socket
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
}

fn retirement_batch(control: &mut TcpStream, run: u64, seq: &mut u64, ids: &[u64]) {
    *seq += 1;
    let mut bytes = udp_frame(6, run, 0, *seq, 48 + ids.len() * 8);
    for (chunk, id) in bytes[48..].as_chunks_mut::<8>().0.iter_mut().zip(ids) {
        chunk.copy_from_slice(&id.to_be_bytes());
    }
    control.write_all(&bytes).unwrap();
    let response = read_frame(control);
    assert_eq!(response[8], 7);
    assert_eq!(
        u64::from_be_bytes(response[28..36].try_into().unwrap()),
        *seq
    );
}

fn wait_active(control: &mut TcpStream, run: u64, seq: &mut u64, expected: u64) {
    let start = Instant::now();
    loop {
        *seq += 1;
        control.write_all(&udp_frame(7, run, 0, *seq, 48)).unwrap();
        let response = read_frame(control);
        assert_eq!(response.len(), 112);
        assert_eq!(response[8], 7);
        let active = u64::from_be_bytes(response[80..88].try_into().unwrap());
        // Retirement is applied asynchronously by the owning server worker.
        assert!(
            active >= expected,
            "retirement released a different live flow: {active} < {expected}"
        );
        if active == expected {
            return;
        }
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "retired flows still active: {active}, wanted {expected}"
        );
        thread::sleep(TICK);
    }
}

fn udp_retirement_safety(address: SocketAddr) {
    eprintln!("case: repeated control retirement and stale UDP frames ({address})");
    let run = 0xbeef_0000_0000 | std::process::id() as u64;
    let mut control = connect(address);
    // Multiple live flows may overlap a target of one while closes arrive.
    let mut registration = udp_frame(1, run, 1, 300_000_000, 48);
    registration[36..44].copy_from_slice(&30_000_000_000u64.to_be_bytes());
    control.write_all(&registration).unwrap();
    assert_eq!(read_frame(&mut control)[8], 2);
    let sockets: Vec<_> = (0..5)
        .map(|_| {
            let socket = UdpSocket::bind(SocketAddr::new(address.ip(), 0)).unwrap();
            socket.connect(address).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            socket
        })
        .collect();
    for flow in 1..=3 {
        assert_eq!(
            udp_roundtrip(&sockets[flow - 1], &udp_frame(3, run, flow as u64, 0, 48))[8],
            4
        );
    }
    let mut seq = 0;
    wait_active(&mut control, run, &mut seq, 3);
    // Deliberately omit the unreliable CLOSE datagram and retire over TCP.
    retirement_batch(&mut control, run, &mut seq, &[1]);
    wait_active(&mut control, run, &mut seq, 2);
    udp_ignored(&sockets[0], &udp_frame(3, run, 1, 0, 48));
    udp_ignored(&sockets[0], &udp_frame(5, run, 1, 1, 128));
    assert_eq!(
        udp_roundtrip(&sockets[3], &udp_frame(3, run, 4, 0, 48))[8],
        4
    );
    // Late datagram and duplicate control retirements must be idempotent.
    sockets[0].send(&udp_frame(6, run, 1, 0, 48)).unwrap();
    retirement_batch(&mut control, run, &mut seq, &[1, 1]);
    // Give the owner time to process duplicate retirements before inspecting
    // every still-live flow, including the replacement with a newer ID.
    thread::sleep(Duration::from_millis(150));
    wait_active(&mut control, run, &mut seq, 3);
    for flow in 2..=4 {
        let request = udp_frame(5, run, flow as u64, 1, 128);
        assert_eq!(udp_roundtrip(&sockets[flow - 1], &request), request);
    }
    retirement_batch(&mut control, run, &mut seq, &[2, 3, 4]);
    wait_active(&mut control, run, &mut seq, 0);
    assert_eq!(
        udp_roundtrip(&sockets[4], &udp_frame(3, run, 5, 0, 48))[8],
        4
    );
    wait_active(&mut control, run, &mut seq, 1);
    seq += 1;
    control.write_all(&udp_frame(8, run, 0, seq, 48)).unwrap();
    assert_eq!(read_frame(&mut control)[8], 7);
}

struct Peer {
    socket: UdpSocket,
    held: Option<Vec<u8>>,
    injected: bool,
}
#[derive(Clone, Copy)]
enum ProxyFault {
    DuplicateReorder,
    DropClose,
}
#[derive(Default)]
struct ProxyReport {
    reordered_flows: usize,
    dropped_closes: usize,
}
struct Proxy {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<io::Result<ProxyReport>>>,
}
fn pump(
    source: &mut TcpStream,
    destination: &mut TcpStream,
    pending: &mut Vec<u8>,
) -> io::Result<()> {
    let mut bytes = [0; 4096];
    match source.read(&mut bytes) {
        Ok(n) => pending.extend_from_slice(&bytes[..n]),
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
        Err(e) => return Err(e),
    }
    while !pending.is_empty() {
        match destination.write(pending) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => {
                pending.drain(..n);
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
impl Proxy {
    fn start(target: SocketAddr, fault: ProxyFault) -> Self {
        let reservation = Reservation::bind(target.ip(), 0).unwrap();
        let address = reservation.address();
        let Reservation { tcp, _udp: udp } = reservation;
        tcp.set_nonblocking(true).unwrap();
        udp.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let worker = thread::spawn(move || {
            let mut report = ProxyReport::default();
            let mut peers: HashMap<SocketAddr, Peer> = HashMap::new();
            let mut control: Option<(TcpStream, TcpStream)> = None;
            let (mut upstream, mut downstream) = (Vec::new(), Vec::new());
            let mut bytes = [0; 65536];
            while !stopping.load(Ordering::Relaxed) {
                if control.is_none() {
                    match tcp.accept() {
                        Ok((client, _)) => {
                            let server =
                                TcpStream::connect_timeout(&target, Duration::from_secs(1))?;
                            client.set_nonblocking(true)?;
                            server.set_nonblocking(true)?;
                            client.set_nodelay(true)?;
                            server.set_nodelay(true)?;
                            control = Some((client, server));
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                        Err(e) => return Err(e),
                    }
                }
                if let Some((client, server)) = &mut control {
                    pump(client, server, &mut upstream)?;
                    pump(server, client, &mut downstream)?;
                }
                loop {
                    let (n, source) = match udp.recv_from(&mut bytes) {
                        Ok(value) => value,
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) => return Err(e),
                    };
                    if matches!(fault, ProxyFault::DropClose) && n >= 48 && bytes[8] == 6 {
                        report.dropped_closes += 1;
                        continue;
                    }
                    if let std::collections::hash_map::Entry::Vacant(entry) = peers.entry(source) {
                        let socket = UdpSocket::bind(SocketAddr::new(target.ip(), 0))?;
                        socket.connect(target)?;
                        socket.set_nonblocking(true)?;
                        entry.insert(Peer {
                            socket,
                            held: None,
                            injected: false,
                        });
                    }
                    peers[&source].socket.send(&bytes[..n])?;
                }
                for (source, peer) in &mut peers {
                    loop {
                        let n = match peer.socket.recv(&mut bytes) {
                            Ok(n) => n,
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                            Err(e) => return Err(e),
                        };
                        if matches!(fault, ProxyFault::DuplicateReorder)
                            && n >= 48
                            && bytes[8] == 5
                            && !peer.injected
                        {
                            if let Some(first) = peer.held.take() {
                                udp.send_to(&bytes[..n], *source)?;
                                udp.send_to(&first, *source)?;
                                udp.send_to(&first, *source)?;
                                peer.injected = true;
                            } else {
                                peer.held = Some(bytes[..n].to_vec());
                            }
                        } else {
                            udp.send_to(&bytes[..n], *source)?;
                        }
                    }
                }
                thread::sleep(Duration::from_millis(1));
            }
            report.reordered_flows = peers.values().filter(|peer| peer.injected).count();
            Ok(report)
        });
        Self {
            address,
            stop,
            worker: Some(worker),
        }
    }
    fn finish(mut self) -> ProxyReport {
        self.stop.store(true, Ordering::Relaxed);
        self.worker
            .take()
            .unwrap()
            .join()
            .expect("proxy panicked")
            .expect("proxy failed")
    }
}
impl Drop for Proxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[test]
fn loopback_recording_modes_multiworker() {
    let _lock = suite_lock();
    let root = Scratch::new();
    let mut sources = Sources::new();
    for server_mode in ["events", "summary", "off"] {
        let (mut server, address) = start_server_recording(&root, false, server_mode, 2);
        let server_dir = server.out.with_extension("");
        let mut server_requests = 0;
        for tcp in [false, true] {
            for mode in ["events", "summary", "off"] {
                let name = format!("{server_mode}-{mode}-{}", if tcp { "tcp" } else { "udp" });
                eprintln!("recording case: {name}");
                let (range, reservation) = sources.take(address.ip());
                let mut args = client_args(&root, &name, address, tcp, &range, false, "1.2");
                let workers = args.iter().position(|arg| arg == "-w").unwrap();
                args[workers + 1] = "3".into();
                let host = args.pop().unwrap();
                args.extend(strings(&["-L", mode]));
                args.push(host);
                drop(reservation);
                let mut client = Process::spawn(&root, &name, &args);
                client.wait_for(|out| out.contains("LOAD | warmup complete"));
                if mode == "off" {
                    assert_no_recording_threads(&client);
                }
                if server_mode == "off" {
                    assert_no_recording_threads(&server);
                }
                let result = client.finish();
                result.success();
                assert!(
                    result.out.contains("server req/resp"),
                    "missing STATS: {}",
                    result.out
                );
                let received = counter(&result.out, "received");
                assert!(received > 0);
                assert_eq!(counter(&result.out, "sent"), received);
                let dir = root.path(&name);
                let final_report = fs::read_to_string(dir.join("server-final.txt")).unwrap();
                let final_report: HashMap<_, _> = final_report
                    .lines()
                    .map(|line| line.split_once(' ').unwrap())
                    .collect();
                assert_eq!(final_report["active"], "0", "END did not retire all flows");
                assert_eq!(final_report["request"].parse::<u64>().unwrap(), received);
                assert_eq!(final_report["response"].parse::<u64>().unwrap(), received);
                server_requests += received;
                assert!(fs::read_to_string(dir.join("client-final.txt"))
                    .unwrap()
                    .contains("complete true"));
                let summaries = recording_artifacts(&dir, mode, Some(3));
                if mode == "summary" {
                    let lines: Vec<_> = result
                        .out
                        .lines()
                        .filter(|line| line.starts_with("RTT summary:"))
                        .collect();
                    assert_eq!(lines.len(), 1, "{}", result.out);
                    assert!(
                        result.out.find("Finished |").unwrap()
                            < result.out.find("RTT summary:").unwrap()
                    );
                    let console_samples: u64 = lines[0]
                        .split("samples=")
                        .nth(1)
                        .unwrap()
                        .split_whitespace()
                        .next()
                        .unwrap()
                        .parse()
                        .unwrap();
                    let rows: Vec<_> = summaries.iter().map(|path| summary_row(path)).collect();
                    let samples: u64 = rows
                        .iter()
                        .map(|row| row["rtt_samples"].parse::<u64>().unwrap())
                        .sum();
                    assert_eq!(samples, received);
                    assert_eq!(console_samples, samples);
                    assert!(rows.iter().all(|row| row["role"] == "client"));
                    let mean_ns: f64 = rows
                        .iter()
                        .map(|row| {
                            row["rtt_avg_ns"].parse::<f64>().unwrap()
                                * row["rtt_samples"].parse::<f64>().unwrap()
                        })
                        .sum::<f64>()
                        / samples as f64;
                    let console_mean_ms: f64 = lines[0]
                        .split(" = ")
                        .nth(1)
                        .unwrap()
                        .split('/')
                        .nth(1)
                        .unwrap()
                        .parse()
                        .unwrap();
                    assert!((console_mean_ms * 1e6 - mean_ns).abs() < 0.51);
                } else if mode == "off" {
                    assert!(!result.out.contains("RTT"), "{}", result.out);
                }
                if mode != "events" {
                    for file in [
                        "summary.csv",
                        "sessions.csv",
                        "recordings.csv",
                        "errors.csv",
                        "forward.csv",
                        "forward-summary.csv",
                    ] {
                        assert!(
                            !dir.join(file).exists(),
                            "unexpected analysis file: {name}/{file}"
                        );
                    }
                } else {
                    assert!(result.out.contains("RTT"));
                    assert!(dir.join("summary.csv").is_file());
                    assert!(dir.join("sessions.csv").is_file());
                }
            }
        }
        server.interrupt();
        let result = server.finish();
        result.success();
        let summaries = recording_artifacts(&server_dir, server_mode, None);
        if server_mode == "summary" {
            let rows: Vec<_> = summaries.iter().map(|path| summary_row(path)).collect();
            assert!(rows.iter().all(|row| row["role"] == "server"));
            for counter in ["server_request", "server_response"] {
                assert_eq!(
                    rows.iter()
                        .map(|row| row[counter].parse::<u64>().unwrap())
                        .sum::<u64>(),
                    server_requests
                );
            }
        }
    }
}

fn assert_no_recording_threads(process: &Process) {
    let tasks = fs::read_dir(format!("/proc/{}/task", process.child.id())).unwrap();
    let mut seen = 0;
    for task in tasks {
        match fs::read_to_string(task.unwrap().path().join("comm")) {
            Ok(name) => {
                // Linux truncates comm at 15 bytes, including finalizer names.
                assert!(
                    !name.starts_with("flowgen-record") && !name.starts_with("flowgen-finaliz"),
                    "off mode thread: {name}"
                );
                seen += 1;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => panic!("read thread name: {error}"),
        }
    }
    assert!(seen >= 2, "process was not running multiple threads");
}

fn recording_artifacts(dir: &Path, mode: &str, workers: Option<usize>) -> Vec<PathBuf> {
    let files: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    let events: Vec<_> = files
        .iter()
        .filter(|path| path.extension().is_some_and(|ext| ext == "fgr"))
        .collect();
    let summaries: Vec<_> = files
        .iter()
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .ends_with(".summary.csv")
        })
        .cloned()
        .collect();
    match mode {
        "events" => {
            assert!(summaries.is_empty());
            assert!(!events.is_empty());
            if let Some(workers) = workers {
                assert_eq!(events.len(), workers);
            }
            for path in events {
                let bytes = fs::read(path).unwrap();
                assert_eq!(&bytes[..8], b"FGRLOG\r\n");
                assert_eq!(
                    bytes[bytes.len() - 4],
                    255,
                    "missing footer: {}",
                    path.display()
                );
            }
        }
        "summary" => {
            assert!(events.is_empty());
            assert!(!summaries.is_empty());
            if let Some(workers) = workers {
                assert_eq!(summaries.len(), workers);
            }
        }
        "off" => {
            assert!(events.is_empty());
            assert!(summaries.is_empty());
        }
        _ => unreachable!(),
    }
    summaries
}

fn summary_row(path: &Path) -> HashMap<String, String> {
    let csv = fs::read_to_string(path).unwrap();
    let mut lines = csv.lines();
    let columns: Vec<_> = lines.next().unwrap().split(',').collect();
    let rows: Vec<_> = lines
        .filter(|line| line.starts_with("aggregate,"))
        .collect();
    assert_eq!(rows.len(), 1, "{}", path.display());
    let values: Vec<_> = rows[0].split(',').collect();
    assert_eq!(values.len(), columns.len());
    columns
        .into_iter()
        .zip(values)
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect()
}

#[test]
fn help_and_version_work_anywhere_without_starting_a_run() {
    let root = Scratch::new();
    for flag in ["-h", "-v"] {
        let expected = if flag == "-h" {
            "Usage: flowgen".to_owned()
        } else {
            format!("flowgen {}", env!("CARGO_PKG_VERSION"))
        };
        for args in [
            vec![flag],
            vec![flag, "-u", "192.168.201.2", "-T", "86400"],
            vec!["-u", flag, "192.168.201.2", "-T", "86400"],
            vec!["-u", "192.168.201.2", "-T", "86400", flag],
            vec!["-s", "--stats", flag],
            vec!["-R", "missing-recordings", flag],
        ] {
            let output = Command::new(BIN)
                .args(&args)
                .current_dir(&root.0)
                .output()
                .unwrap();
            assert!(output.status.success(), "{args:?}: {:?}", output);
            assert!(output.stderr.is_empty(), "{args:?}: {:?}", output);
            assert!(String::from_utf8(output.stdout)
                .unwrap()
                .starts_with(&expected));
            assert!(!root.path("results").exists());
        }
    }
}

#[test]
fn loopback_cli_and_faults() {
    let _lock = suite_lock();
    let root = Scratch::new();
    let mut sources = Sources::new();
    for ipv6 in [false, true] {
        let (mut server, address) = start_server(&root, ipv6);
        if !ipv6 {
            for tcp in [false, true] {
                let name = if tcp {
                    "unlimited-tcp"
                } else {
                    "unlimited-udp"
                };
                let (range, reservation) = sources.take(address.ip());
                let mut args = client_args(&root, name, address, tcp, &range, true, "0");
                if tcp {
                    let index = args.iter().position(|arg| arg == "-T").unwrap();
                    args.splice(index..index + 2, ["-T0".to_owned()]);
                }
                drop(reservation);
                // Three sessions + one worker need 107 descriptors, so 64
                // exercises automatic adjustment before either protocol runs.
                let mut client = Process::spawn_with_file_limit(&root, name, &args, Some(64));
                client.wait_for(|out| out.matches("req/resp ").count() >= 4);
                assert!(client.child.try_wait().unwrap().is_none());
                assert!(client.output().contains("duration: unlimited"));
                assert!(!client.output().contains("DRAIN"));
                if tcp {
                    client.interrupt();
                } else {
                    assert_eq!(
                        unsafe { libc::kill(client.child.id() as libc::pid_t, libc::SIGTERM) },
                        0
                    );
                }
                healthy(&client.finish());
                inspect_recording(&root.path(name), true);
                offline(&root, name);
            }
        }
        for tcp in [false, true] {
            for churn in [false, true] {
                let name = format!(
                    "{}-{}-{}",
                    if ipv6 { "v6" } else { "v4" },
                    if tcp { "tcp" } else { "udp" },
                    if churn { "churn" } else { "fixed" }
                );
                eprintln!("case: {name}");
                let (range, reservation) = sources.take(address.ip());
                let args = client_args(&root, &name, address, tcp, &range, churn, "0.4");
                drop(reservation);
                let started = Instant::now();
                let result = Process::spawn(&root, &name, &args).finish();
                healthy(&result);
                assert!(
                    started.elapsed() >= Duration::from_millis(650),
                    "warmup/load duration shortened"
                );
                for key in ["duplicate", "reordered"] {
                    assert_eq!(counter(&result.out, key), 0);
                }
                inspect_recording(&root.path(&name), churn);
                offline(&root, &name);
            }
        }
        eprintln!("case: TCP split/coalesced/malformed/partial frames ({address})");
        tcp_frames(address);
        for tcp in [false, true] {
            occupied_warmup(&root, &mut sources, address, tcp, false);
            if !ipv6 {
                occupied_warmup(&root, &mut sources, address, tcp, true);
            }
        }
        udp_retirement_safety(address);
        single_tuple_reuse(&root, &mut sources, address);
        if !ipv6 {
            eprintln!("case: UDP proxy duplicate/reorder");
            let proxy = Proxy::start(address, ProxyFault::DuplicateReorder);
            let (range, reservation) = sources.take(address.ip());
            let args = client_args(&root, "proxy", proxy.address, false, &range, false, "0.4");
            drop(reservation);
            let result = Process::spawn(&root, "proxy", &args).finish();
            healthy(&result);
            assert_eq!(counter(&result.out, "duplicate"), 3, "{}", result.out);
            assert_eq!(counter(&result.out, "reordered"), 3, "{}", result.out);
            assert_eq!(
                proxy.finish().reordered_flows,
                3,
                "faults were not injected into all sessions"
            );
            inspect_recording(&root.path("proxy"), false);
            offline(&root, "proxy");
            eprintln!("case: UDP churn with all CLOSE datagrams dropped");
            let proxy = Proxy::start(address, ProxyFault::DropClose);
            let (range, reservation) = sources.take(address.ip());
            let args = client_args(
                &root,
                "dropped-close",
                proxy.address,
                false,
                &range,
                true,
                "0.8",
            );
            drop(reservation);
            let result = Process::spawn(&root, "dropped-close", &args).finish();
            healthy(&result);
            let events = recording_events(&root.path("dropped-close"));
            let ready = events.iter().filter(|e| e[36] == 1).count();
            assert!(
                ready >= 5,
                "control retirement failed to admit replacements"
            );
            assert_eq!(
                events.iter().filter(|e| e[36] == 7).count(),
                0,
                "replacement setup failed"
            );
            assert_eq!(
                proxy.finish().dropped_closes + 3,
                ready,
                "turnover must use CLOSE; the final three flows use reliable END"
            );
            inspect_recording(&root.path("dropped-close"), true);
            offline(&root, "dropped-close");
            for tcp in [false, true] {
                let name = if tcp {
                    "interrupt-tcp"
                } else {
                    "interrupt-udp"
                };
                eprintln!("case: {name}");
                let (range, reservation) = sources.take(address.ip());
                let args = client_args(&root, name, address, tcp, &range, false, "30");
                drop(reservation);
                let mut client = Process::spawn(&root, name, &args);
                client.wait_for(|out| out.contains("LOAD | warmup complete"));
                client.wait_for(|out| out.contains("req/resp "));
                client.interrupt();
                let result = client.finish();
                healthy(&result);
                inspect_recording(&root.path(name), false);
                offline(&root, name);
            }
        }
        server.interrupt();
        let result = server.finish();
        result.success();
    }
    // Bind without listen so the control connect is refused while no competing
    // listener can claim our selected destination port.
    let unavailable = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
    unavailable
        .bind(&"127.0.0.1:0".parse::<SocketAddr>().unwrap().into())
        .unwrap();
    let address = unavailable.local_addr().unwrap().as_socket().unwrap();
    for tcp in [false, true] {
        let name = if tcp { "absent-tcp" } else { "absent-udp" };
        eprintln!("case: {name}");
        let (range, reservation) = sources.take(address.ip());
        let args = client_args(&root, name, address, tcp, &range, false, "0.4");
        drop(reservation);
        let result = Process::spawn(&root, name, &args).finish();
        assert!(
            !result.status.success(),
            "missing server unexpectedly succeeded"
        );
        assert!(
            result.err.to_ascii_lowercase().contains("refused"),
            "{}",
            result.err
        );
        assert!(!result.out.contains("LOAD |"));
    }
    eprintln!("case: insufficient source tuple pool");
    let (range, reservation) = sources.take(address.ip());
    let low = range.split('-').next().unwrap();
    let args = client_args(
        &root,
        "pool-small",
        address,
        false,
        &format!("{low}-{low}"),
        false,
        "0.4",
    );
    drop(reservation);
    let result = Process::spawn(&root, "pool-small", &args).finish();
    assert!(!result.status.success());
    assert!(
        result.err.contains("source tuple capacity 1") && result.err.contains("required 3"),
        "{}",
        result.err
    );
    assert!(!result.out.contains("LOAD |"));
}
