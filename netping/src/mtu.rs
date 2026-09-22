use crate::{
    client,
    mtu_socket::{NetworkError, ProbeSocket},
    net::{self, Reactor},
    options::{Mode, Options},
};
use mio::Events;
use std::{
    fs::File,
    io::{self, Read, Write},
    time::{Duration, Instant},
};

const TRIES: usize = 3;

#[derive(Debug)]
enum Reply {
    Ok(Duration),
    TooBig { mtu: Option<usize>, local: bool },
    Timeout,
    Stop(&'static str),
    Failed(String),
}

impl From<NetworkError> for Reply {
    fn from(e: NetworkError) -> Self {
        match e {
            NetworkError::TooBig { mtu, local } => Self::TooBig { mtu, local },
            NetworkError::Other(errno) => {
                Self::Failed(io::Error::from_raw_os_error(errno).to_string())
            }
        }
    }
}

struct Runner<'a> {
    options: &'a Options,
    socket: ProbeSocket,
    reactor: &'a mut Reactor,
    events: Events,
    attempts: u64,
    end: Instant,
    next: Instant,
    overhead: usize,
}

impl Runner<'_> {
    fn stop(&self) -> Option<&'static str> {
        if self.reactor.stopped() {
            Some("interrupted")
        } else if Instant::now() >= self.end {
            Some("duration limit reached")
        } else {
            None
        }
    }

    fn probe(&mut self, size: usize, control: bool) -> io::Result<Reply> {
        let reply = self.attempt(size)?;
        let result = match &reply {
            Reply::Ok(rtt) => format!("OK  {:.3} ms", rtt.as_secs_f64() * 1000.0),
            Reply::TooBig { mtu, local } => format!(
                "TOO_BIG  mtu={} ({})",
                mtu.map_or_else(|| "unknown".into(), |n| n.to_string()),
                if *local { "local" } else { "ICMP" }
            ),
            Reply::Timeout => "TIMEOUT".into(),
            Reply::Stop(reason) => format!("STOP  {reason}"),
            Reply::Failed(reason) => format!("ERROR  {reason}"),
        };
        println!(
            "{size:7} {:7}  {result}{}",
            size - self.overhead,
            if control { " [control]" } else { "" }
        );
        io::stdout().flush()?;
        Ok(reply)
    }

    fn attempt(&mut self, size: usize) -> io::Result<Reply> {
        if self.options.count.is_some_and(|n| self.attempts >= n) {
            return Ok(Reply::Stop("probe count limit reached"));
        }
        loop {
            if let Some(reason) = self.stop() {
                return Ok(Reply::Stop(reason));
            }
            if Instant::now() >= self.next {
                break;
            }
            client::poll(self.reactor, &mut self.events, self.next.min(self.end))?;
            self.socket.clear_errors()?;
            // Drain old echo replies so an edge-triggered poll cannot spin while pacing.
            let _ = self.socket.reply(0, 0);
        }
        self.socket.clear_errors()?;
        self.attempts += 1;
        let payload = size - self.overhead;
        let request = self.socket.request(self.attempts, payload);
        let start = Instant::now();
        self.next = start + self.options.interval;
        if let Err(e) = self.socket.send(&request) {
            return Ok(self
                .socket
                .error(&request)?
                .map_or_else(|| Reply::Failed(e.to_string()), Reply::from));
        }
        let deadline = (start + self.options.timeout).min(self.end);
        loop {
            if let Some(reason) = self.stop() {
                return Ok(Reply::Stop(reason));
            }
            if Instant::now() >= deadline {
                return Ok(Reply::Timeout);
            }
            if let Some(e) = self.socket.error(&request)? {
                return Ok(e.into());
            }
            match self.socket.reply(self.attempts, payload) {
                Ok(true) => {
                    let now = Instant::now();
                    return Ok(if now < deadline {
                        Reply::Ok(now.duration_since(start))
                    } else {
                        Reply::Timeout
                    });
                }
                Ok(false) => {}
                Err(e) => {
                    if let Some(error) = self.socket.error(&request)? {
                        return Ok(error.into());
                    }
                    return Ok(Reply::Failed(e.to_string()));
                }
            }
            if Instant::now() >= deadline {
                return Ok(Reply::Timeout);
            }
            client::poll(self.reactor, &mut self.events, deadline)?;
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Status {
    Confirmed,
    LowerBound,
    Suspected,
    Inconclusive,
}

#[derive(Debug)]
struct Finding {
    largest: usize,
    status: Status,
    reason: String,
}

fn inconclusive(largest: usize, reason: impl Into<String>) -> Finding {
    Finding {
        largest,
        status: Status::Inconclusive,
        reason: reason.into(),
    }
}

fn check(
    size: usize,
    baseline: usize,
    probe: &mut impl FnMut(usize, bool) -> io::Result<Reply>,
) -> io::Result<Reply> {
    for _ in 0..TRIES {
        match probe(size, false)? {
            Reply::Timeout => {
                let mut reachable = false;
                for _ in 0..TRIES {
                    match probe(baseline, true)? {
                        Reply::Ok(_) => {
                            reachable = true;
                            break;
                        }
                        Reply::Timeout => {}
                        Reply::TooBig { .. } => {
                            return Ok(Reply::Failed(
                                "small control no longer fits; path changed".into(),
                            ))
                        }
                        other => return Ok(other),
                    }
                }
                if !reachable {
                    return Ok(Reply::Failed(
                        "small controls also timed out; MTU cannot be inferred".into(),
                    ));
                }
            }
            other => return Ok(other),
        }
    }
    Ok(Reply::Timeout)
}

fn search(
    base: usize,
    cap: usize,
    probe: &mut impl FnMut(usize, bool) -> io::Result<Reply>,
) -> io::Result<Finding> {
    let mut reachable = false;
    for _ in 0..TRIES {
        match probe(base, true)? {
            Reply::Ok(_) => {
                reachable = true;
                break;
            }
            Reply::Timeout => {}
            Reply::Stop(reason) => return Ok(inconclusive(0, reason)),
            Reply::Failed(reason) => return Ok(inconclusive(0, reason)),
            Reply::TooBig { .. } => return Ok(inconclusive(0, "even the baseline is too large")),
        }
    }
    if !reachable {
        return Ok(inconclusive(
            0,
            "no baseline reply; check reachability, ICMP filtering or UDP server support",
        ));
    }
    let (mut low, mut high) = (base, cap);
    let mut explicit = None;
    let mut bounded = false;
    let mut candidate = 1500.min(cap).max(base);
    while low < high {
        match check(candidate, base, probe)? {
            Reply::Ok(_) => low = candidate,
            Reply::TooBig { mtu, .. } => {
                let bound = mtu.filter(|n| *n < candidate).unwrap_or(candidate - 1);
                if bound < low {
                    return Ok(inconclusive(
                        low,
                        "Too Big contradicts a successful probe; path may have changed",
                    ));
                }
                explicit = Some(explicit.map_or(bound, |old: usize| old.min(bound)));
                high = high.min(bound);
                bounded = true;
            }
            Reply::Timeout => {
                high = candidate - 1;
                bounded = true;
            }
            Reply::Stop(reason) => return Ok(inconclusive(low, reason)),
            Reply::Failed(reason) => return Ok(inconclusive(low, reason)),
        }
        if low < high {
            candidate = if bounded {
                low + (high - low).div_ceil(2)
            } else {
                high
            };
        }
    }
    match check(low, base, probe)? {
        Reply::Ok(_) => {}
        Reply::Stop(reason) => return Ok(inconclusive(low, reason)),
        Reply::Failed(reason) => return Ok(inconclusive(low, reason)),
        _ => {
            return Ok(inconclusive(
                low,
                "final size did not verify; path or reachability changed",
            ))
        }
    }
    let status = if explicit == Some(low) {
        Status::Confirmed
    } else if low == cap {
        Status::LowerBound
    } else {
        Status::Suspected
    };
    Ok(Finding {
        largest: low,
        status,
        reason: String::new(),
    })
}

pub fn run(o: &Options, r: &mut Reactor) -> Result<bool, Box<dyn std::error::Error>> {
    let addr = net::resolve(
        o.host.as_ref().unwrap(),
        o.v6,
        if o.mode == Mode::Icmp { 0 } else { o.port },
    )?;
    let mut bytes = [0; 8];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    let socket = ProbeSocket::new(o, addr, u64::from_ne_bytes(bytes).max(1), r)?;
    let overhead = if o.v6 { 48 } else { 28 };
    let cap = o.size + overhead;
    let base = o.size.min(64) + overhead;
    let start = Instant::now();
    println!(
        "netping | {} MTU | {} | IP size <= {cap} bytes",
        if o.mode == Mode::Icmp { "ICMP" } else { "UDP" },
        addr.ip()
    );
    println!(
        "{}; {} tries per size; timeout {:.3}s",
        if o.mode == Mode::Icmp {
            "Echo replies may also be affected by the return path"
        } else {
            "Forward probes with 32-byte server acknowledgements"
        },
        TRIES,
        o.timeout.as_secs_f64()
    );
    println!("IP SIZE PAYLOAD  RESULT");
    let mut runner = Runner {
        options: o,
        socket,
        reactor: r,
        events: Events::with_capacity(16),
        attempts: 0,
        end: start + o.duration.unwrap_or(Duration::from_secs(60)),
        next: start,
        overhead,
    };
    let result = search(base, cap, &mut |size, control| runner.probe(size, control))?;
    println!(
        "\n--- MTU results | {} probes | {:.3} s ---",
        runner.attempts,
        start.elapsed().as_secs_f64()
    );
    if result.largest > 0 {
        println!(
            "Largest confirmed IP size: {} bytes (payload {})",
            result.largest,
            result.largest - overhead
        );
    }
    match result.status {
        Status::Confirmed => println!(
            "Path MTU = {} bytes (Too Big bound verified)",
            result.largest
        ),
        Status::LowerBound => println!(
            "Path MTU >= {} bytes (search limit reached)",
            result.largest
        ),
        Status::Suspected => {
            println!(
                "{} bytes: timeout in {TRIES}/{TRIES} probes with successful small controls",
                result.largest + 1
            );
            println!("Result: suspected size limit / MTU black hole; not a confirmed PMTU");
        }
        Status::Inconclusive => println!("Result: inconclusive ({})", result.reason),
    }
    Ok(matches!(
        result.status,
        Status::Confirmed | Status::LowerBound
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_errors_are_verified_and_search_cap_is_only_a_lower_bound() {
        for hint in [Some(1400), None] {
            let r = search(92, 9000, &mut |size, _| {
                Ok(if size <= 1400 {
                    Reply::Ok(Duration::ZERO)
                } else {
                    Reply::TooBig {
                        mtu: hint,
                        local: false,
                    }
                })
            })
            .unwrap();
            assert_eq!(r.largest, 1400);
            assert_eq!(r.status, Status::Confirmed);
        }
        let r = search(112, 9000, &mut |_, _| Ok(Reply::Ok(Duration::ZERO))).unwrap();
        assert_eq!(r.largest, 9000);
        assert_eq!(r.status, Status::LowerBound);
    }

    #[test]
    fn black_holes_need_small_controls_and_never_claim_confirmed_mtu() {
        let r = search(92, 1500, &mut |size, _| {
            Ok(if size <= 1400 {
                Reply::Ok(Duration::ZERO)
            } else {
                Reply::Timeout
            })
        })
        .unwrap();
        assert_eq!(r.largest, 1400);
        assert_eq!(r.status, Status::Suspected);
        let mut attempts = 0;
        let r = search(92, 1500, &mut |_, _| {
            attempts += 1;
            Ok(if attempts == 1 {
                Reply::Ok(Duration::ZERO)
            } else {
                Reply::Timeout
            })
        })
        .unwrap();
        assert_eq!(r.status, Status::Inconclusive);
        assert!(r.reason.contains("controls"));
    }

    #[test]
    fn transient_loss_stops_and_conflicting_bounds_do_not_fabricate_mtu() {
        let mut dropped = false;
        let r = search(92, 1500, &mut |size, _| {
            Ok(if size == 1500 && !dropped {
                dropped = true;
                Reply::Timeout
            } else {
                Reply::Ok(Duration::ZERO)
            })
        })
        .unwrap();
        assert_eq!(r.status, Status::LowerBound);
        let r = search(92, 1500, &mut |size, _| {
            Ok(if size == 92 {
                Reply::Ok(Duration::ZERO)
            } else {
                Reply::TooBig {
                    mtu: Some(80),
                    local: false,
                }
            })
        })
        .unwrap();
        assert_eq!(r.status, Status::Inconclusive);
        let r = search(92, 1500, &mut |_, _| Ok(Reply::Stop("interrupted"))).unwrap();
        assert_eq!(r.largest, 0);
        assert_eq!(r.status, Status::Inconclusive);
    }
}
