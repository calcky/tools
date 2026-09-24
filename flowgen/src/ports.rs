use crate::options::{Config, MAX_SESSIONS, MAX_SOURCES, MAX_WORKERS};
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashSet};
use std::fs;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

const RESERVED_PORTS: &str = "/proc/sys/net/ipv4/ip_local_reserved_ports";
const MAX_REUSE_BYTES: u64 = 128 * 1024 * 1024;

type CoolingTuple = Reverse<(Instant, u64)>;

struct ReusePool {
    delay: Duration,
    active: Vec<bool>,
    cooling: BinaryHeap<CoolingTuple>,
}

/// A single destination's source-tuple pool, shared under the engine's mutex.
/// Allocation consumes a fresh tuple before the caller attempts to bind/connect.
/// Occupied ports therefore count as attempts and are never silently retried.
pub struct TuplePool {
    sources: Vec<IpAddr>,
    ports: Vec<u16>,
    capacity: u64,
    cursor: u64,
    reused: u64,
    reuse: Option<ReusePool>,
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn allocation_error(error: std::collections::TryReserveError) -> io::Error {
    io::Error::other(format!("cannot allocate bounded tuple-pool state: {error}"))
}

fn read_reserved_ports() -> io::Result<Vec<(u16, u16)>> {
    let contents = fs::read_to_string(RESERVED_PORTS)
        .map_err(|e| io::Error::new(e.kind(), format!("cannot read {RESERVED_PORTS}: {e}")))?;
    parse_reserved_ports(&contents).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid {RESERVED_PORTS}: {e}"),
        )
    })
}

fn parse_reserved_ports(contents: &str) -> io::Result<Vec<(u16, u16)>> {
    let contents = contents.trim();
    if contents.is_empty() {
        return Ok(Vec::new());
    }
    let mut ranges = Vec::new();
    for item in contents.split(',') {
        if ranges.len() == u16::MAX as usize + 1 {
            return Err(invalid("too many reserved-port ranges"));
        }
        let item = item.trim();
        let (low, high) = item.split_once('-').unwrap_or((item, item));
        let low = low
            .parse::<u16>()
            .map_err(|_| invalid(format!("bad port: {low}")))?;
        let high = high
            .parse::<u16>()
            .map_err(|_| invalid(format!("bad port: {high}")))?;
        if low > high {
            return Err(invalid(format!("reversed reserved-port range: {item}")));
        }
        ranges.push((low, high));
    }
    Ok(ranges)
}

impl TuplePool {
    pub fn new(
        sources: Vec<IpAddr>,
        range: (u16, u16),
        reuse: Option<Duration>,
    ) -> io::Result<Self> {
        Self::with_reserved(sources, range, reuse, &read_reserved_ports()?)
    }

    fn with_reserved(
        mut sources: Vec<IpAddr>,
        range: (u16, u16),
        reuse: Option<Duration>,
        reserved: &[(u16, u16)],
    ) -> io::Result<Self> {
        if sources.is_empty() || sources.len() > MAX_SOURCES {
            return Err(invalid(format!(
                "tuple pool requires 1..{MAX_SOURCES} source IPs"
            )));
        }
        if range.0 == 0 || range.0 > range.1 {
            return Err(invalid(
                "source-port range must be ordered and within 1..65535",
            ));
        }
        let ipv6 = sources[0].is_ipv6();
        if sources
            .iter()
            .any(|ip| ip.is_ipv6() != ipv6 || ip.is_unspecified() || ip.is_multicast())
        {
            return Err(invalid(
                "tuple sources must be concrete unicast IPs of one family",
            ));
        }
        let mut seen = HashSet::new();
        sources.retain(|source| seen.insert(*source));

        // The fixed port bitmap avoids work proportional to ports times ranges.
        let mut excluded = vec![false; u16::MAX as usize + 1];
        for &(low, high) in reserved {
            if low > high {
                return Err(invalid("reversed reserved-port range"));
            }
            excluded[usize::from(low)..=usize::from(high)].fill(true);
        }
        let ports: Vec<u16> = (range.0..=range.1)
            .filter(|p| !excluded[usize::from(*p)])
            .collect();
        let capacity = (sources.len() as u64)
            .checked_mul(ports.len() as u64)
            .ok_or_else(|| invalid("tuple capacity overflow"))?;
        let reuse = match reuse {
            Some(delay) => {
                if delay.is_zero() || Instant::now().checked_add(delay).is_none() {
                    return Err(invalid(
                        "tuple reuse delay must be positive and representable",
                    ));
                }
                let bytes = reuse_bytes(capacity)?;
                if bytes > MAX_REUSE_BYTES {
                    return Err(invalid(format!(
                        "tuple reuse state needs {bytes} bytes, exceeding its {MAX_REUSE_BYTES}-byte budget; narrow -B/-P"
                    )));
                }
                let slots = usize::try_from(capacity)
                    .map_err(|_| invalid("tuple capacity exceeds address space"))?;
                let mut active = Vec::new();
                active.try_reserve_exact(slots).map_err(allocation_error)?;
                active.resize(slots, false);
                let mut cooling = BinaryHeap::new();
                // At most one cooldown entry per inactive tuple, across all generations.
                cooling.try_reserve_exact(slots).map_err(allocation_error)?;
                Some(ReusePool {
                    delay,
                    active,
                    cooling,
                })
            }
            None => None,
        };
        Ok(Self {
            sources,
            ports,
            capacity,
            cursor: 0,
            reused: 0,
            reuse,
        })
    }

    pub fn capacity(&self) -> u64 {
        self.capacity
    }

    /// Number of distinct tuples ever allocated, including failed network attempts.
    pub fn used(&self) -> u64 {
        self.cursor
    }

    /// Number of allocations from expired cooldown entries, excluding fresh tuples.
    pub fn reused(&self) -> u64 {
        self.reused
    }

    pub fn allocate(&mut self, now: Instant) -> Option<SocketAddr> {
        let index = if self.cursor < self.capacity {
            let index = self.cursor;
            self.cursor += 1;
            if let Some(reuse) = &mut self.reuse {
                reuse.active[index as usize] = true;
            }
            index
        } else {
            let reuse = self.reuse.as_mut()?;
            let &Reverse((deadline, index)) = reuse.cooling.peek()?;
            if deadline > now {
                return None;
            }
            reuse.cooling.pop();
            reuse.active[index as usize] = true;
            self.reused = self.reused.saturating_add(1);
            index
        };
        let ports = self.ports.len() as u64;
        Some(SocketAddr::new(
            self.sources[(index / ports) as usize],
            self.ports[(index % ports) as usize],
        ))
    }

    /// Release a currently owned tuple exactly once, after closing its socket.
    /// The address-only API cannot distinguish a stale release from a later lease.
    pub fn release(&mut self, addr: SocketAddr, now: Instant) {
        let Some(reuse) = &mut self.reuse else { return };
        let Some(source) = self.sources.iter().position(|ip| *ip == addr.ip()) else {
            return;
        };
        let Ok(port) = self.ports.binary_search(&addr.port()) else {
            return;
        };
        let index = source as u64 * self.ports.len() as u64 + port as u64;
        if index >= self.cursor || !reuse.active[index as usize] {
            return;
        }
        reuse.active[index as usize] = false;
        // An unrepresentable deadline permanently retires the tuple rather than
        // wrapping the clock and making it eligible for premature reuse.
        if let Some(deadline) = now.checked_add(reuse.delay) {
            reuse.cooling.push(Reverse((deadline, index)));
        }
    }
}

fn reuse_bytes(capacity: u64) -> io::Result<u64> {
    capacity
        .checked_mul((std::mem::size_of::<bool>() + std::mem::size_of::<CoolingTuple>()) as u64)
        .ok_or_else(|| invalid("tuple reuse memory estimate overflow"))
}

/// Validate resources and maximize the process file limit within permissions.
/// The supplied capacity must exclude reserved ports.
/// Estimates cover bounded application buffers, not kernel socket memory or disk.
pub fn preflight(config: &Config, capacity: u64) -> io::Result<()> {
    if config.analyze.is_some() {
        return Ok(());
    }
    let required = check_resources(config, capacity, u64::MAX)?;
    // SAFETY: getrlimit writes a properly sized, initialized rlimit structure.
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        let error = io::Error::last_os_error();
        return Err(io::Error::new(
            error.kind(),
            format!("cannot read RLIMIT_NOFILE: {error}"),
        ));
    }
    let minimum = libc::rlim_t::try_from(required)
        .map_err(|_| invalid("file descriptor requirement exceeds platform limit"))?;
    // Linux rejects RLIM_INFINITY for NOFILE: fs.nr_open is its ceiling.
    let ceiling = fs::read_to_string("/proc/sys/fs/nr_open")
        .ok()
        .and_then(|value| value.trim().parse::<libc::rlim_t>().ok())
        .filter(|&value| value > 0 && value != libc::RLIM_INFINITY)
        .unwrap_or(limit.rlim_max.max(minimum));
    let mut failure = None;
    for target in [
        ceiling.max(limit.rlim_cur),
        limit.rlim_max.min(ceiling).max(limit.rlim_cur),
    ] {
        if target == limit.rlim_cur {
            continue;
        }
        let raised = libc::rlimit {
            rlim_cur: target,
            rlim_max: limit.rlim_max.max(target),
        };
        // SAFETY: setrlimit reads a valid structure and changes only this process.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raised) } == 0 {
            limit = raised;
            break;
        }
        failure = Some(io::Error::last_os_error());
    }
    if limit.rlim_cur < minimum {
        let error =
            failure.unwrap_or_else(|| invalid("system file limit is below the requirement"));
        return Err(io::Error::new(
            error.kind(),
            format!(
                "cannot raise RLIMIT_NOFILE to {required} (soft={}, hard={}): {error}; raise the process/container file limit (ulimit -n {required}){}",
                limit.rlim_cur, limit.rlim_max,
                if config.server { "" } else { " or reduce -c/-w" }
            ),
        ));
    }
    Ok(())
}

fn check_resources(config: &Config, capacity: u64, nofile: u64) -> io::Result<u64> {
    if config.workers == 0 || config.workers > MAX_WORKERS {
        return Err(invalid("worker count exceeds practical limits"));
    }
    if config.server {
        // Only startup overhead is known here; clients control live sessions.
        let startup_descriptors = config.workers as u64 * 8 + 96;
        if nofile < startup_descriptors {
            return Err(invalid(format!(
                "RLIMIT_NOFILE is {nofile}, need at least {startup_descriptors} for server workers and control/reserve descriptors"
            )));
        }
        return Ok(startup_descriptors);
    }
    if config.sessions == 0
        || config.sessions > MAX_SESSIONS
        || config.workers == 0
        || config.workers > MAX_WORKERS
    {
        return Err(invalid("session or worker count exceeds practical limits"));
    }
    if !(48..=65507).contains(&config.length) {
        return Err(invalid("application message length must be 48..65507"));
    }
    if !config.turnover.is_finite()
        || config.turnover < 0.0
        || !config.pps.is_finite()
        || config.pps <= 0.0
    {
        return Err(invalid(
            "turnover must be finite/nonnegative and PPS finite/positive",
        ));
    }
    if config.warmup.is_zero() || config.timeout.is_zero() {
        return Err(invalid("warmup and timeout durations must be positive"));
    }
    let sessions = config.sessions as u64;
    if !config.server {
        // An unlimited run can only reserve its initial population in advance.
        let replacements = (config.turnover * config.duration.as_secs_f64()).ceil();
        // u64::MAX rounds up to 2^64 as f64; reject that boundary before casting.
        if !replacements.is_finite() || replacements < 0.0 || replacements >= u64::MAX as f64 {
            return Err(invalid("N + ceil(U*T) tuple demand overflow"));
        }
        let demand = sessions
            .checked_add(replacements as u64)
            .ok_or_else(|| invalid("N + ceil(U*T) tuple demand overflow"))?;
        let required = if config.reuse.is_some() {
            sessions
        } else {
            demand
        };
        if capacity < required {
            return Err(invalid(format!(
                "source tuple capacity {capacity} is below required {required} (N={}, ceil(U*T)={}); add -B addresses or widen -P{}",
                sessions, replacements as u64,
                if config.reuse.is_none() { "; -Q explicitly permits cooldown reuse" } else { "" }
            )));
        }
    }
    // Include epoll/listeners/recorders per worker, 16 server controls, a client
    // control connection, and descriptors inherited or opened during reporting.
    let descriptor_need = (config.workers as u64)
        .checked_mul(8)
        .and_then(|n| n.checked_add(sessions))
        .and_then(|n| n.checked_add(32 + 64))
        .ok_or_else(|| invalid("file descriptor estimate overflow"))?;
    if descriptor_need > nofile {
        return Err(invalid(format!(
            "RLIMIT_NOFILE is {nofile}, need at least {descriptor_need} for {} sessions, {} workers and control/reserve descriptors",
            config.sessions, config.workers
        )));
    }
    // Budget one request's bookkeeping per pacing slot inside the timeout,
    // plus a boundary slot. Buffers and per-flow state are estimated separately.
    let outstanding = (config.pps * config.timeout.as_secs_f64()).ceil();
    if !outstanding.is_finite() || outstanding >= u64::MAX as f64 {
        return Err(invalid("outstanding-request memory estimate overflow"));
    }
    let pending_bytes = (outstanding as u64)
        .checked_add(1)
        .and_then(|n| n.checked_mul(64))
        .ok_or_else(|| invalid("outstanding-request memory estimate overflow"))?;
    let per_session = (config.length as u64)
        .checked_mul(4)
        .and_then(|n| n.checked_add(4096))
        .and_then(|n| n.checked_add(pending_bytes))
        .ok_or_else(|| invalid("per-session memory estimate overflow"))?;
    let worker_bytes = (config.workers as u64)
        .checked_mul(2 * 1024 * 1024)
        .ok_or_else(|| invalid("worker memory estimate overflow"))?;
    let pool_bytes = if !config.server && config.reuse.is_some() {
        let bytes = reuse_bytes(capacity)?;
        if bytes > MAX_REUSE_BYTES {
            return Err(invalid(
                "tuple reuse state exceeds its 128 MiB budget; narrow -B/-P",
            ));
        }
        bytes
    } else {
        0
    };
    let _application_bytes = sessions
        .checked_mul(per_session)
        .and_then(|n| n.checked_add(worker_bytes))
        .and_then(|n| n.checked_add(pool_bytes))
        .ok_or_else(|| invalid("application memory estimate overflow"))?;
    Ok(descriptor_need)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sources() -> Vec<IpAddr> {
        vec!["192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap()]
    }

    fn config(args: &[&str]) -> Config {
        crate::options::parse(args.iter().map(|s| (*s).to_owned())).unwrap()
    }

    #[test]
    fn fresh_tuples_unique_failed_attempts_consumed_and_exhaustion_permanent() {
        let mut pool = TuplePool::with_reserved(sources(), (65533, 65535), None, &[]).unwrap();
        let now = Instant::now();
        let mut allocated = HashSet::new();
        for used in 1..=6 {
            let addr = pool.allocate(now).unwrap();
            assert!(allocated.insert(addr));
            pool.release(addr, now); // Also models a failed bind/connect attempt.
            assert_eq!(pool.used(), used);
        }
        assert_eq!(pool.capacity(), 6);
        assert_eq!(pool.reused(), 0);
        assert_eq!(pool.allocate(now + Duration::from_secs(100)), None);
    }

    #[test]
    fn reserved_ranges_and_duplicate_sources_do_not_inflate_capacity() {
        let mut ips = sources();
        ips.push(ips[0]);
        let reserved = parse_reserved_ports("99-101,103,103-105,65535\n").unwrap();
        let mut pool = TuplePool::with_reserved(ips, (100, 106), None, &reserved).unwrap();
        assert_eq!(pool.capacity(), 4);
        let mut ports = Vec::new();
        while let Some(addr) = pool.allocate(Instant::now()) {
            ports.push(addr.port());
        }
        assert_eq!(ports, vec![102, 106, 102, 106]);
        let mut empty = TuplePool::with_reserved(sources(), (103, 104), None, &reserved).unwrap();
        assert_eq!(empty.capacity(), 0);
        assert!(empty.allocate(Instant::now()).is_none());
    }

    #[test]
    fn fresh_before_expired_reuse_and_exact_cooldown() {
        let delay = Duration::from_secs(2);
        let now = Instant::now();
        let mut pool =
            TuplePool::with_reserved(vec![sources()[0]], (100, 102), Some(delay), &[]).unwrap();
        let first = pool.allocate(now).unwrap();
        pool.release(first, now);
        assert_eq!(pool.allocate(now + delay).unwrap().port(), 101);
        assert_eq!(pool.allocate(now + delay).unwrap().port(), 102);
        assert_eq!(pool.used(), 3);
        assert_eq!(pool.reused(), 0);
        assert_eq!(pool.allocate(now + delay - Duration::from_nanos(1)), None);
        assert_eq!(pool.allocate(now + delay), Some(first));
        assert_eq!(pool.used(), 3);
        assert_eq!(pool.reused(), 1);
        assert_eq!(pool.allocate(now + delay), None);
    }

    #[test]
    fn reuse_state_bounded_and_duplicate_or_foreign_releases_ignored() {
        let now = Instant::now();
        let delay = Duration::from_millis(10);
        let mut pool =
            TuplePool::with_reserved(vec![sources()[0]], (100, 100), Some(delay), &[]).unwrap();
        let addr = SocketAddr::new(sources()[0], 100);
        pool.release(addr, now); // Never allocated.
        pool.release(SocketAddr::new(sources()[1], 100), now);
        pool.release(SocketAddr::new(sources()[0], 99), now);
        assert_eq!(pool.reuse.as_ref().unwrap().cooling.len(), 0);
        let initial_capacity = pool.reuse.as_ref().unwrap().cooling.capacity();
        for generation in 0..1000 {
            let time = now + delay * generation;
            assert_eq!(pool.allocate(time), Some(addr));
            assert_eq!(pool.allocate(time), None);
            pool.release(addr, time);
            pool.release(addr, time);
            let state = pool.reuse.as_ref().unwrap();
            assert_eq!(state.cooling.len(), 1);
            assert_eq!(state.cooling.capacity(), initial_capacity);
            assert_eq!(state.active.len(), 1);
        }
        assert_eq!(pool.used(), 1);
        assert_eq!(pool.reused(), 999);
    }

    #[test]
    fn earliest_deadline_first_even_if_releases_arrive_out_of_order() {
        let now = Instant::now();
        let delay = Duration::from_secs(1);
        let mut pool =
            TuplePool::with_reserved(vec![sources()[0]], (100, 101), Some(delay), &[]).unwrap();
        let later = pool.allocate(now).unwrap();
        let earlier = pool.allocate(now).unwrap();
        pool.release(later, now + delay);
        pool.release(earlier, now);
        assert_eq!(pool.allocate(now + delay), Some(earlier));
        assert_eq!(pool.allocate(now + delay), None);
        assert_eq!(pool.allocate(now + delay * 2), Some(later));
    }

    #[test]
    fn shared_mutex_coordinates_workers() {
        use std::sync::{Arc, Mutex};
        let pool = Arc::new(Mutex::new(
            TuplePool::with_reserved(sources(), (100, 199), None, &[]).unwrap(),
        ));
        let threads: Vec<_> = (0..4)
            .map(|_| {
                let pool = Arc::clone(&pool);
                std::thread::spawn(move || {
                    let mut addrs = Vec::new();
                    loop {
                        let next = pool.lock().unwrap().allocate(Instant::now());
                        match next {
                            Some(addr) => addrs.push(addr),
                            None => break,
                        }
                    }
                    addrs
                })
            })
            .collect();
        let all: Vec<_> = threads
            .into_iter()
            .flat_map(|t| t.join().unwrap())
            .collect();
        assert_eq!(all.len(), 200);
        assert_eq!(all.into_iter().collect::<HashSet<_>>().len(), 200);
        assert_eq!(pool.lock().unwrap().used(), 200);
    }

    #[test]
    fn validates_ranges_sources_reuse_memory_and_kernel_reserved_syntax() {
        for value in [
            ",", "1,", "1,,2", "abc", "1-", "-2", "10-1", "65536", "1-2-3",
        ] {
            assert!(parse_reserved_ports(value).is_err(), "accepted {value:?}");
        }
        assert!(parse_reserved_ports("\n").unwrap().is_empty());
        assert_eq!(
            parse_reserved_ports("0,1-65535").unwrap(),
            vec![(0, 0), (1, 65535)]
        );
        assert!(TuplePool::with_reserved(vec![], (1, 2), None, &[]).is_err());
        assert!(TuplePool::with_reserved(sources(), (0, 2), None, &[]).is_err());
        assert!(TuplePool::with_reserved(sources(), (2, 1), None, &[]).is_err());
        assert!(TuplePool::with_reserved(
            vec![sources()[0], "::1".parse().unwrap()],
            (1, 2),
            None,
            &[]
        )
        .is_err());
        assert!(TuplePool::with_reserved(sources(), (1, 2), Some(Duration::ZERO), &[]).is_err());
        assert!(TuplePool::with_reserved(sources(), (1, 2), Some(Duration::MAX), &[]).is_err());
        assert!(reuse_bytes(u64::MAX).is_err());
        let many_sources = (1..=128)
            .map(|last| IpAddr::from([192, 0, 2, last]))
            .collect();
        assert!(TuplePool::with_reserved(
            many_sources,
            (1, 65535),
            Some(Duration::from_secs(1)),
            &[]
        )
        .is_err());
    }

    #[test]
    fn reads_actual_reserved_settings_without_modification() {
        let reserved = read_reserved_ports().unwrap();
        let mut pool =
            TuplePool::new(vec!["127.0.0.1".parse().unwrap()], (1, 65535), None).unwrap();
        while let Some(addr) = pool.allocate(Instant::now()) {
            assert!(!reserved
                .iter()
                .any(|&(low, high)| (low..=high).contains(&addr.port())));
        }
        assert_eq!(pool.capacity(), pool.used());
    }

    #[test]
    fn preflight_checks_cumulative_and_fractional_demand_and_reuse() {
        let mut c = config(&["-u", "-c", "100", "-U", "1.25", "-T", "2.5", "localhost"]);
        assert!(check_resources(&c, 103, u64::MAX)
            .unwrap_err()
            .to_string()
            .contains("required 104"));
        check_resources(&c, 104, u64::MAX).unwrap();
        c.reuse = Some(Duration::from_secs(1));
        check_resources(&c, 100, u64::MAX).unwrap();
        assert!(check_resources(&c, 99, u64::MAX).is_err());
        c.turnover = 0.0;
        c.reuse = None;
        check_resources(&c, 100, u64::MAX).unwrap();
        assert!(check_resources(&c, 99, u64::MAX).is_err());
    }

    #[test]
    fn unlimited_preflight_checks_initial_population_and_timeouts() {
        let mut c = config(&["-u", "-c", "100", "-U", "5", "-T0", "localhost"]);
        check_resources(&c, 100, u64::MAX).unwrap();
        assert!(check_resources(&c, 99, u64::MAX).is_err());
        c.timeout = Duration::ZERO;
        assert!(check_resources(&c, 100, u64::MAX).is_err());
        c.timeout = Duration::from_secs(1);
        c.warmup = Duration::ZERO;
        assert!(check_resources(&c, 100, u64::MAX).is_err());
    }

    #[test]
    fn preflight_file_limits_both_modes_and_large_memory_estimates() {
        let mut c = config(&["-t", "-c", "10", "-w", "2", "localhost"]);
        let needed = 10 + 2 * 8 + 96;
        check_resources(&c, 10, needed).unwrap();
        assert!(check_resources(&c, 10, needed - 1)
            .unwrap_err()
            .to_string()
            .contains("RLIMIT_NOFILE"));
        c.server = true;
        let startup = 2 * 8 + 96;
        check_resources(&c, 0, startup).unwrap();
        assert!(check_resources(&c, 0, startup - 1).is_err());
        // Server preflight must not use the client's target or request budget.
        c.sessions = MAX_SESSIONS;
        c.length = 65507;
        check_resources(&c, 0, startup).unwrap();
        c.server = false;
        check_resources(&c, u64::MAX, u64::MAX).unwrap();
        let default_server = config(&["-s"]);
        check_resources(&default_server, 0, u64::MAX).unwrap();
    }

    #[test]
    fn preflight_rejects_arithmetic_overflow_and_nonfinite_manual_configs() {
        let mut c = config(&["-t", "localhost"]);
        c.turnover = u64::MAX as f64;
        c.duration = Duration::from_secs(1);
        assert!(check_resources(&c, u64::MAX, u64::MAX)
            .unwrap_err()
            .to_string()
            .contains("overflow"));
        c.turnover = f64::MAX;
        c.duration = Duration::MAX;
        assert!(check_resources(&c, u64::MAX, u64::MAX).is_err());
        c.turnover = f64::NAN;
        assert!(check_resources(&c, u64::MAX, u64::MAX).is_err());
        c.turnover = 0.0;
        c.pps = f64::INFINITY;
        assert!(check_resources(&c, u64::MAX, u64::MAX).is_err());
        c.pps = f64::MAX;
        c.timeout = Duration::MAX;
        assert!(check_resources(&c, u64::MAX, u64::MAX)
            .unwrap_err()
            .to_string()
            .contains("memory estimate overflow"));
        let offline = config(&["-R", "recordings"]);
        preflight(&offline, 0).unwrap();
    }

    #[test]
    fn preflight_adjusts_file_limit_in_isolated_process() {
        const CASE: &str = "FLOWGEN_TEST_NOFILE_CASE";
        if let Ok(case) = std::env::var(CASE) {
            let ceiling: libc::rlim_t = fs::read_to_string("/proc/sys/fs/nr_open")
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            let original = match case.as_str() {
                "system-max" => libc::rlimit {
                    rlim_cur: 1024,
                    rlim_max: ceiling,
                },
                "raise-soft" => libc::rlimit {
                    rlim_cur: 1024,
                    rlim_max: 4096,
                },
                "sufficient" => libc::rlimit {
                    rlim_cur: 2048,
                    rlim_max: 4096,
                },
                "hard-denied" => libc::rlimit {
                    rlim_cur: 1024,
                    rlim_max: 1024,
                },
                "server" => libc::rlimit {
                    rlim_cur: 64,
                    rlim_max: 4096,
                },
                _ => panic!("unknown test case"),
            };
            // These limits affect only this test subprocess, never the harness.
            assert_eq!(
                unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &original) },
                0
            );
            if unsafe { libc::geteuid() } == 0 {
                assert_eq!(unsafe { libc::setuid(65534) }, 0);
            }
            let c = if case == "server" {
                config(&["-s", "-w", "4"])
            } else {
                config(&["-u", "-c", "1000", "-w", "4", "localhost"])
            };
            let result = preflight(&c, 1000);
            let mut actual = original;
            assert_eq!(
                unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut actual) },
                0
            );
            if case == "hard-denied" {
                let error = result.unwrap_err().to_string();
                assert!(
                    error.contains("cannot raise RLIMIT_NOFILE to 1128"),
                    "{error}"
                );
                assert!(error.contains("soft=1024, hard=1024"), "{error}");
                assert!(error.contains("ulimit -n 1128"), "{error}");
                assert_eq!(actual.rlim_cur, original.rlim_cur);
            } else {
                result.unwrap();
                assert_eq!(actual.rlim_cur, original.rlim_max);
            }
            assert_eq!(actual.rlim_max, original.rlim_max);
            return;
        }
        for case in [
            "system-max",
            "raise-soft",
            "sufficient",
            "hard-denied",
            "server",
        ] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "ports::tests::preflight_adjusts_file_limit_in_isolated_process",
                    "--nocapture",
                ])
                .env(CASE, case)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{case}: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[test]
    fn preflight_budgets_outstanding_requests_and_reads_actual_file_limit() {
        let small = config(&["-t", "-c", "1", "-w", "1", "localhost"]);
        preflight(&small, 1).unwrap();
        let large = config(&[
            "-t",
            "-c",
            "1000",
            "-r",
            "1000000",
            "-W",
            "86400",
            "localhost",
        ]);
        check_resources(&large, 1000, u64::MAX).unwrap();
    }
}
