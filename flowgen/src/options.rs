use std::collections::HashSet;
use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const HELP: &str = "Usage: flowgen -t|-u [options] HOST | flowgen -s [options] | flowgen -R DIR
  -s          Serve TCP/control and UDP (no session count limit)
  -t / -u     Client TCP / UDP data protocol; choose exactly one
  -c COUNT    Client target sessions (default: 1000)
  -a SECONDS  Positive warmup duration (default: 10)
  -U RATE     Replacements per second after warmup (default: 0)
  -r PPS      Requests per second per session (default: 10)
  -l BYTES    Application message length, 48..65507 (default: 128)
  -T SECONDS  Load duration, excluding warmup (default: 60)
  -W SECONDS  Setup/request/drain timeout (default: 1)
  -w COUNT    Workers (default: min(4, available CPUs))
  -L MODE     Recording mode: events, summary, or off (default: events)
  -A CPUS     Pin workers to CPUs, e.g. 0-3,8 (Linux)
  -S BYTES    Requested socket send buffer size
  -D BYTES    Requested socket receive buffer size
  -b COUNT    Listen backlog (server only, default: 4096)
  -B IP       Local source IP, repeatable; must already exist on the host
  -P LOW-HIGH Source-port range (default: Linux ephemeral range)
  -Q SECONDS  Allow tuple reuse after this positive cooldown, fresh tuples first
  -p PORT     Destination/listen port (default: 11112)
  -4 / -6     IPv4 (default) / IPv6
  -o DIR      Recording directory (default: results/flowgen[-server]-<unique>)
  -R DIR      Offline analysis; cannot be combined with runtime arguments
  -h / -v     Help / version
Times accept fractional seconds, from 0.000001 through 86400.
Limits: 1000000 sessions, 256 workers, 1024 source IPs, 1000000 PPS or replacements/s.
Linux reserved source ports are excluded. No tuple reuse unless -Q is supplied.
Server mode accepts -s, -w, -L, -A, -S, -D, -b, -p, -4/-6 and -o.
";

pub(crate) const MAX_SESSIONS: usize = 1_000_000;
pub(crate) const MAX_WORKERS: usize = 256;
pub(crate) const MAX_SOURCES: usize = 1024;
pub(crate) const DEFAULT_BACKLOG: i32 = 4096;
pub(crate) const MAX_SOCKET_BUFFER: usize = i32::MAX as usize / 2;

#[derive(Clone, Debug)]
pub struct Config {
    pub server: bool,
    pub tcp: bool,
    pub host: Option<String>,
    pub sessions: usize,
    pub warmup: Duration,
    pub turnover: f64,
    pub pps: f64,
    pub length: usize,
    pub duration: Duration,
    pub timeout: Duration,
    pub workers: usize,
    pub recording: String,
    pub cpus: Option<Vec<usize>>,
    pub send_buffer: Option<usize>,
    pub recv_buffer: Option<usize>,
    pub backlog: i32,
    pub sources: Vec<IpAddr>,
    pub ports: (u16, u16),
    pub reuse: Option<Duration>,
    pub port: u16,
    pub ipv6: bool,
    pub output: PathBuf,
    pub analyze: Option<PathBuf>,
}

fn seconds(value: &str, option: &str) -> Result<Duration, String> {
    let n: f64 = value
        .parse()
        .map_err(|_| format!("{option}: invalid seconds: {value}"))?;
    if !n.is_finite() || !(0.000001..=86400.0).contains(&n) {
        return Err(format!("{option}: seconds must be 0.000001..86400"));
    }
    Duration::try_from_secs_f64(n).map_err(|_| format!("{option}: unrepresentable duration"))
}

fn rate(value: &str, option: &str, allow_zero: bool) -> Result<f64, String> {
    let n: f64 = value
        .parse()
        .map_err(|_| format!("{option}: invalid rate: {value}"))?;
    if !n.is_finite() || n < 0.0 || n > 1_000_000.0 || (!allow_zero && n == 0.0) {
        return Err(format!(
            "{option}: rate must be finite, {} and <= 1000000",
            if allow_zero {
                "nonnegative"
            } else {
                "positive"
            }
        ));
    }
    if n > 0.0 {
        let interval = Duration::try_from_secs_f64(1.0 / n)
            .map_err(|_| format!("{option}: rate is too small to schedule"))?;
        if std::time::Instant::now().checked_add(interval).is_none() {
            return Err(format!("{option}: rate is too small to schedule"));
        }
    }
    Ok(n)
}

fn validate_pacing(config: &Config) -> Result<(), String> {
    // A partitioned pacer can schedule one worker stride beyond the load
    // horizon. Checking only 1/rate misses overflow in worker_index/rate.
    let horizon = config.warmup + config.duration + config.timeout * 3 + Duration::from_secs(60);
    let epoch = std::time::Instant::now()
        .checked_add(horizon)
        .ok_or("run horizon cannot be represented by the monotonic clock")?;
    for (option, rate, stride) in [
        ("-r", config.pps, 1),
        ("-U", config.turnover, config.workers),
    ] {
        if rate == 0.0 {
            continue;
        }
        let span = Duration::try_from_secs_f64(stride as f64 * (1.0 / rate))
            .map_err(|_| format!("{option}: rate is too small for the worker count/run horizon"))?;
        if epoch.checked_add(span).is_none() {
            return Err(format!(
                "{option}: rate is too small for the worker count/run horizon"
            ));
        }
    }
    Ok(())
}

fn count(value: &str, option: &str, maximum: usize) -> Result<usize, String> {
    let n = value
        .parse::<usize>()
        .map_err(|_| format!("{option}: invalid integer: {value}"))?;
    if n == 0 || n > maximum {
        return Err(format!("{option}: value must be 1..{maximum}"));
    }
    Ok(n)
}

fn socket_buffer(value: &str, option: &str) -> Result<usize, String> {
    let bytes = value
        .parse::<usize>()
        .map_err(|_| format!("{option}: invalid byte count: {value}"))?;
    if bytes == 0 || bytes > MAX_SOCKET_BUFFER {
        return Err(format!("{option}: bytes must be 1..{}", MAX_SOCKET_BUFFER));
    }
    Ok(bytes)
}

fn cpu_list(value: &str) -> Result<Vec<usize>, String> {
    let mut cpus = Vec::new();
    for item in value.split(',') {
        if item.is_empty() {
            return Err("-A: expected comma-separated CPU numbers or ranges".into());
        }
        let (first, last) = item
            .split_once('-')
            .map_or((item, item), |(first, last)| (first, last));
        let first = first
            .parse::<usize>()
            .map_err(|_| format!("-A: invalid CPU range: {item}"))?;
        let last = last
            .parse::<usize>()
            .map_err(|_| format!("-A: invalid CPU range: {item}"))?;
        if first > last {
            return Err(format!("-A: CPU range is reversed: {item}"));
        }
        if last == usize::MAX {
            return Err(format!("-A: CPU number is too large: {item}"));
        }
        for cpu in first..=last {
            if cpus.contains(&cpu) {
                return Err(format!("-A: duplicate CPU {cpu}"));
            }
            cpus.push(cpu);
            if cpus.len() > MAX_WORKERS {
                return Err(format!("-A: at most {MAX_WORKERS} CPUs"));
            }
        }
    }
    if cpus.is_empty() {
        return Err("-A: CPU list cannot be empty".into());
    }
    Ok(cpus)
}

fn port_range(value: &str) -> Result<(u16, u16), String> {
    let (low, high) = value
        .split_once('-')
        .ok_or_else(|| "-P: expected LOW-HIGH".to_string())?;
    let low = count(low, "-P", u16::MAX as usize)? as u16;
    let high = count(high, "-P", u16::MAX as usize)? as u16;
    if low > high {
        return Err("-P: lower port exceeds upper port".into());
    }
    Ok((low, high))
}

fn ephemeral_range() -> Result<(u16, u16), String> {
    const PATH: &str = "/proc/sys/net/ipv4/ip_local_port_range";
    let contents = fs::read_to_string(PATH).map_err(|e| format!("cannot read {PATH}: {e}"))?;
    parse_ephemeral_range(&contents).map_err(|e| format!("invalid {PATH}: {e}"))
}

fn parse_ephemeral_range(contents: &str) -> Result<(u16, u16), String> {
    let mut fields = contents.split_whitespace();
    let low = fields.next().ok_or("missing lower port")?;
    let high = fields.next().ok_or("missing upper port")?;
    if fields.next().is_some() {
        return Err("expected exactly two ports".into());
    }
    port_range(&format!("{low}-{high}"))
}

fn output_directory(server: bool) -> PathBuf {
    static SERIAL: AtomicU64 = AtomicU64::new(0);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let serial = SERIAL.fetch_add(1, Ordering::Relaxed);
    let prefix = if server { "flowgen-server" } else { "flowgen" };
    PathBuf::from(format!(
        "results/{prefix}-{timestamp}-{}-{serial}",
        std::process::id()
    ))
}

/// Parse arguments excluding the executable name. Help/version are handled by main.
/// Empty sources mean the engine should resolve the route's local source address.
pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Config, String> {
    let mut config = Config {
        server: false,
        tcp: false,
        host: None,
        sessions: 1000,
        warmup: Duration::from_secs(10),
        turnover: 0.0,
        pps: 10.0,
        length: 128,
        duration: Duration::from_secs(60),
        timeout: Duration::from_secs(1),
        workers: std::thread::available_parallelism().map_or(1, |n| n.get().min(4)),
        recording: "events".into(),
        cpus: None,
        send_buffer: None,
        recv_buffer: None,
        backlog: DEFAULT_BACKLOG,
        sources: Vec::new(),
        ports: (0, 0),
        reuse: None,
        port: 11112,
        ipv6: false,
        output: PathBuf::new(),
        analyze: None,
    };
    let mut args = args.into_iter();
    let mut seen = HashSet::new();
    let mut source_set = HashSet::new();
    while let Some(arg) = args.next() {
        if !arg.starts_with('-') {
            if arg.is_empty() || config.host.replace(arg).is_some() {
                return Err("specify exactly one nonempty target HOST".into());
            }
            continue;
        }
        if !matches!(
            arg.as_str(),
            "-s" | "-t"
                | "-u"
                | "-c"
                | "-a"
                | "-U"
                | "-r"
                | "-l"
                | "-T"
                | "-W"
                | "-w"
                | "-A"
                | "-S"
                | "-D"
                | "-b"
                | "-L"
                | "-B"
                | "-P"
                | "-Q"
                | "-p"
                | "-4"
                | "-6"
                | "-o"
                | "-R"
        ) {
            return Err(format!("unknown option {arg}; use -h"));
        }
        if !seen.insert(arg.clone()) && arg != "-B" {
            return Err(format!("{arg}: option specified more than once"));
        }
        match arg.as_str() {
            "-s" => config.server = true,
            "-t" => config.tcp = true,
            "-u" => {}
            "-4" => {}
            "-6" => config.ipv6 = true,
            _ => {
                let value = args
                    .next()
                    .ok_or_else(|| format!("{arg} requires a value"))?;
                match arg.as_str() {
                    "-c" => config.sessions = count(&value, &arg, MAX_SESSIONS)?,
                    "-a" => config.warmup = seconds(&value, &arg)?,
                    "-U" => config.turnover = rate(&value, &arg, true)?,
                    "-r" => config.pps = rate(&value, &arg, false)?,
                    "-l" => {
                        config.length = count(&value, &arg, 65507)?;
                        if config.length < 48 {
                            return Err("-l: application message length must be 48..65507".into());
                        }
                    }
                    "-T" => config.duration = seconds(&value, &arg)?,
                    "-W" => config.timeout = seconds(&value, &arg)?,
                    "-w" => config.workers = count(&value, &arg, MAX_WORKERS)?,
                    "-L" => {
                        if !matches!(value.as_str(), "events" | "summary" | "off") {
                            return Err("-L: expected events, summary, or off".into());
                        }
                        config.recording = value;
                    }
                    "-A" => config.cpus = Some(cpu_list(&value)?),
                    "-S" => config.send_buffer = Some(socket_buffer(&value, &arg)?),
                    "-D" => config.recv_buffer = Some(socket_buffer(&value, &arg)?),
                    "-b" => config.backlog = count(&value, &arg, i32::MAX as usize)? as i32,
                    "-B" => {
                        let source: IpAddr = value
                            .parse()
                            .map_err(|_| format!("-B: invalid IP: {value}"))?;
                        if source.is_unspecified() || source.is_multicast() {
                            return Err("-B: specify a concrete unicast source address".into());
                        }
                        if source_set.insert(source) {
                            if config.sources.len() == MAX_SOURCES {
                                return Err(format!("-B: at most {MAX_SOURCES} source addresses"));
                            }
                            config.sources.push(source);
                        }
                    }
                    "-P" => config.ports = port_range(&value)?,
                    "-Q" => config.reuse = Some(seconds(&value, &arg)?),
                    "-p" => config.port = count(&value, &arg, u16::MAX as usize)? as u16,
                    "-o" | "-R" => {
                        if value.is_empty() || value.starts_with('-') {
                            return Err(format!("{arg}: expected a directory (prefix paths starting with '-' with './')"));
                        }
                        if arg == "-o" {
                            config.output = PathBuf::from(value);
                        } else {
                            config.analyze = Some(PathBuf::from(value));
                        }
                    }
                    _ => unreachable!(),
                }
            }
        }
    }

    if config.analyze.is_some() {
        if seen.len() != 1 || config.host.is_some() {
            return Err("-R is mutually exclusive with all runtime arguments".into());
        }
        return Ok(config);
    }
    if seen.contains("-4") && seen.contains("-6") {
        return Err("choose one of -4 or -6".into());
    }
    if seen.contains("-t") && seen.contains("-u") {
        return Err("choose exactly one of -t or -u".into());
    }
    if config.server {
        if config.host.is_some()
            || seen.iter().any(|arg| {
                !matches!(
                    arg.as_str(),
                    "-s" | "-w" | "-L" | "-A" | "-S" | "-D" | "-b" | "-p" | "-4" | "-6" | "-o"
                )
            })
        {
            return Err(
                "server mode accepts -s, -w, -L, -A, -S, -D, -b, -p, -4/-6 and -o; -c is client-only".into(),
            );
        }
    } else {
        if seen.contains("-b") {
            return Err("-b is server-only".into());
        }
        if !seen.contains("-t") && !seen.contains("-u") {
            return Err("client requires an explicit -t or -u".into());
        }
        let host = config
            .host
            .as_deref()
            .ok_or("client requires a target HOST")?;
        if let Ok(ip) = host.parse::<IpAddr>() {
            if ip.is_ipv6() != config.ipv6 {
                return Err("target IP family does not match -4/-6".into());
            }
        }
    }
    if config.sources.iter().any(|ip| ip.is_ipv6() != config.ipv6) {
        return Err("-B source IP family does not match -4/-6".into());
    }
    if !config.server {
        config.workers = config.workers.min(config.sessions);
    }
    if !config.server {
        validate_pacing(&config)?;
    }
    if !seen.contains("-P") {
        config.ports = ephemeral_range()?;
    }
    if !seen.contains("-o") {
        config.output = output_directory(config.server);
    }
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_args(args: &[&str]) -> Result<Config, String> {
        parse(args.iter().map(|s| (*s).to_owned()))
    }

    #[test]
    fn client_and_server_defaults_and_unique_output() {
        let client = parse_args(&["-t", "localhost"]).unwrap();
        let server = parse_args(&["-s"]).unwrap();
        assert!(client.tcp);
        assert_eq!(client.sessions, 1000);
        assert_eq!(client.recording, "events");
        assert!(client.cpus.is_none());
        assert_eq!(client.send_buffer, None);
        assert_eq!(client.recv_buffer, None);
        assert_eq!(client.backlog, DEFAULT_BACKLOG);
        assert_eq!(client.warmup, Duration::from_secs(10));
        assert_eq!(client.duration, Duration::from_secs(60));
        assert_eq!(client.timeout, Duration::from_secs(1));
        assert_eq!(client.ports, ephemeral_range().unwrap());
        assert!(client.sources.is_empty());
        assert!(client
            .output
            .to_str()
            .unwrap()
            .starts_with("results/flowgen-"));
        assert!(server
            .output
            .to_str()
            .unwrap()
            .starts_with("results/flowgen-server-"));
        assert_ne!(
            client.output,
            parse_args(&["-t", "localhost"]).unwrap().output
        );
        assert!(parse_args(&["-c", "19", "-s"]).is_err());
    }

    #[test]
    fn fractional_churn_ipv6_and_repeated_sources() {
        let c = parse_args(&[
            "-u",
            "-6",
            "-c",
            "50000",
            "-a",
            "10.5",
            "-U",
            "10000.5",
            "-r",
            "0.25",
            "-l",
            "48",
            "-T",
            "60.25",
            "-W",
            "0.1",
            "-w",
            "2",
            "-B",
            "::1",
            "-B",
            "::1",
            "-B",
            "2001:db8::2",
            "-P",
            "1024-65535",
            "-Q",
            "1.25",
            "-p",
            "12345",
            "-o",
            "recordings/run",
            "::1",
        ])
        .unwrap();
        assert!(!c.tcp);
        assert!(c.ipv6);
        assert_eq!(c.sessions, 50000);
        assert_eq!(c.warmup, Duration::from_millis(10500));
        assert_eq!(c.duration, Duration::from_millis(60250));
        assert_eq!(c.timeout, Duration::from_millis(100));
        assert_eq!(c.reuse, Some(Duration::from_millis(1250)));
        assert_eq!(c.turnover, 10000.5);
        assert_eq!(c.pps, 0.25);
        assert_eq!(c.sources.len(), 2);
        assert_eq!(c.ports, (1024, 65535));
        assert_eq!(c.port, 12345);
        assert_eq!(c.output, PathBuf::from("recordings/run"));
    }

    #[test]
    fn rejects_bad_combinations_and_families() {
        for args in [
            vec![],
            vec!["localhost"],
            vec!["-t"],
            vec!["-t", "-u", "localhost"],
            vec!["-s", "localhost"],
            vec!["-s", "-t"],
            vec!["-s", "-c", "10000"],
            vec!["-s", "-U", "1"],
            vec!["-t", "-4", "-6", "localhost"],
            vec!["-t", "::1"],
            vec!["-t", "-6", "127.0.0.1"],
            vec!["-t", "-B", "::1", "localhost"],
            vec!["-u", "-6", "-B", "127.0.0.1", "localhost"],
            vec!["-t", "-B", "0.0.0.0", "localhost"],
            vec!["-t", "-B", "224.0.0.1", "localhost"],
            vec!["-t", "one", "two"],
            vec!["-t", "-T"],
            vec!["-t", "-t", "localhost"],
            vec!["--tcp", "localhost"],
            vec!["-L", "1"],
            vec!["-t", "-L", "bad", "localhost"],
            vec!["-t", "-A", "0-2,2", "localhost"],
            vec!["-t", "-A", "3-1", "localhost"],
            vec!["-t", "-A", "0,,2", "localhost"],
            vec!["-t", "-S", "0", "localhost"],
            vec!["-t", "-D", "2147483648", "localhost"],
            vec!["-t", "-b", "1", "localhost"],
            vec!["-t", "-o", "", "localhost"],
        ] {
            assert!(parse_args(&args).is_err(), "accepted {args:?}");
        }
    }

    #[test]
    fn offline_analysis_excludes_runtime_arguments() {
        let c = parse_args(&["-R", "some/recording"]).unwrap();
        assert_eq!(c.analyze, Some(PathBuf::from("some/recording")));
        for extra in [
            vec!["-s"],
            vec!["-t"],
            vec!["host"],
            vec!["-o", "out"],
            vec!["-4"],
            vec!["-c", "1"],
        ] {
            let mut args = vec!["-R", "dir"];
            args.extend(extra);
            assert!(parse_args(&args).is_err(), "accepted {args:?}");
        }
    }

    #[test]
    fn rejects_nonfinite_zero_overflow_and_impractical_values() {
        for option in ["-a", "-T", "-W", "-Q", "-r", "-U"] {
            for value in ["NaN", "inf", "-inf", "-1", "1e100", "abc"] {
                assert!(
                    parse_args(&["-u", option, value, "localhost"]).is_err(),
                    "{option} {value}"
                );
            }
            if option != "-U" {
                assert!(parse_args(&["-t", option, "0", "localhost"]).is_err());
            }
        }
        for (option, value) in [
            ("-c", "0"),
            ("-c", "1000001"),
            ("-c", "18446744073709551616"),
            ("-w", "0"),
            ("-w", "257"),
            ("-l", "47"),
            ("-l", "65508"),
            ("-p", "0"),
            ("-p", "65536"),
            ("-P", "0-100"),
            ("-P", "20-10"),
            ("-P", "1-65536"),
            ("-P", "1-2-3"),
            ("-a", "1e-20"),
            ("-r", "1e-300"),
        ] {
            assert!(
                parse_args(&["-t", option, value, "localhost"]).is_err(),
                "{option} {value}"
            );
        }
        assert_eq!(
            parse_args(&["-u", "-U", "0", "-l", "65507", "localhost"])
                .unwrap()
                .length,
            65507
        );
    }

    #[test]
    fn validates_kernel_ephemeral_range() {
        assert_eq!(
            parse_ephemeral_range("32768\t60999\n").unwrap(),
            (32768, 60999)
        );
        for value in ["", "32768", "0 10", "10 1", "1 65536", "a b", "1 2 3"] {
            assert!(parse_ephemeral_range(value).is_err(), "accepted {value:?}");
        }
    }

    #[test]
    fn tiny_turnover_validates_worker_stride_independent_of_argument_order() {
        for args in [
            vec!["-u", "-c", "32", "-U", "1e-18", "-w", "32", "localhost"],
            vec!["-u", "-c", "32", "-w", "32", "-U", "1e-18", "localhost"],
        ] {
            assert!(
                parse_args(&args).is_err(),
                "accepted overflowing pacer: {args:?}"
            );
        }
        // Choose a rate whose reciprocal fits Duration and Instant on this
        // platform but whose stride of 256 cannot fit Duration anywhere.
        let candidate = 1e-17;
        let interval = Duration::try_from_secs_f64(1.0 / candidate).unwrap();
        if std::time::Instant::now().checked_add(interval).is_some() {
            assert!(rate("1e-17", "-U", true).is_ok());
            assert!(parse_args(&["-u", "-w", "256", "-U", "1e-17", "localhost"]).is_err());
        }
        let c = parse_args(&[
            "-u",
            "-w",
            "256",
            "-U",
            "0.000001",
            "-r",
            "0.000001",
            "localhost",
        ])
        .unwrap();
        assert_eq!(c.turnover, 0.000001);
        assert_eq!(c.pps, 0.000001);
        assert_eq!(
            parse_args(&["-u", "-w", "256", "-U", "0", "localhost"])
                .unwrap()
                .turnover,
            0.0
        );
    }

    #[test]
    fn parses_runtime_tuning_without_changing_defaults() {
        let c = parse_args(&[
            "-u",
            "-L",
            "summary",
            "-A",
            "0-2,8",
            "-S",
            "1048576",
            "-D",
            "2097152",
            "localhost",
        ])
        .unwrap();
        assert_eq!(c.recording, "summary");
        assert_eq!(c.cpus, Some(vec![0, 1, 2, 8]));
        assert_eq!(c.send_buffer, Some(1 << 20));
        assert_eq!(c.recv_buffer, Some(2 << 20));

        let server = parse_args(&["-s", "-b", "8192", "-L", "off"]).unwrap();
        assert_eq!(server.backlog, 8192);
        assert_eq!(server.recording, "off");
    }
}
