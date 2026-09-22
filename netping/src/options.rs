use std::time::Duration;

pub const HELP: &str = "Usage: netping [options] HOST | netping -s [options]
  -S          Inspect TCP MSS once; -t also queries a netping server's send MSS
  -M          Path MTU discovery (ICMP, or UDP with -u and an updated server)
  -w          Live ICMP + UDP + TCP window (TCP echo, or connect with -C)
  -P PORT     TCP port override in window mode (UDP still uses -p)
  -u          UDP echo (requires netping -s)
  -t          TCP echo over one connection (requires netping -s)
  -C          TCP connect time (any TCP server)
              Default: ICMP echo
  -s          Serve UDP and TCP echo on the same port
  -b          Per-second performance reports (default: 1000 PPS, 10s)
  -f          Continuous ping-pong, one outstanding request (requires -b)
  -p PORT     Destination/listen port (default: 11111)
  -c COUNT    Stop sending after COUNT attempts
  -i SECONDS  Send interval; decimals accepted (default: 1, or .001 with -b)
  -r PPS      Send rate; mutually exclusive with -i and -f
  -W SECONDS  Per-request timeout (default: 1)
  -T SECONDS  Sending duration; -c and -T stop at whichever comes first
  -l BYTES    Payload including test header (default: 64); -M: maximum probe payload
  -4 / -6     IPv4 (default) / IPv6
  -h / -v     Help / version
Times are in seconds. RTT/connection measurements are in milliseconds.
Ctrl+C prints a summary. Server mode accepts only -s, -p and -4/-6.
Window: -w rejects -u/-t/-s/-b/-f; rates and counts apply to each protocol.
MTU: -M rejects -t/-C/-s/-w/-b/-f; -c caps all probes, including controls.
MTU defaults: 9000-byte IP ceiling, 100ms pacing, 1s timeout, 60s duration.
MSS: -S accepts HOST, -t, -p, -W and -4/-6; capture needs root/CAP_NET_RAW.
";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Icmp,
    Udp,
    Tcp,
    Connect,
}
impl Mode {
    pub fn name(self) -> &'static str {
        match self {
            Self::Icmp => "ICMP",
            Self::Udp => "UDP",
            Self::Tcp => "TCP echo",
            Self::Connect => "TCP connect",
        }
    }
    pub fn datagram(self) -> bool {
        matches!(self, Self::Icmp | Self::Udp)
    }
}

#[derive(Clone, Debug)]
pub struct Options {
    pub mode: Mode,
    pub server: bool,
    pub window: bool,
    pub mtu: bool,
    pub mss: bool,
    pub tcp_port: Option<u16>,
    pub bench: bool,
    pub flood: bool,
    pub v6: bool,
    pub host: Option<String>,
    pub port: u16,
    pub count: Option<u64>,
    pub interval: Duration,
    pub timeout: Duration,
    pub duration: Option<Duration>,
    pub size: usize,
}

fn seconds(s: &str) -> Result<Duration, String> {
    let n: f64 = s.parse().map_err(|_| format!("invalid seconds: {s}"))?;
    if !n.is_finite() || n <= 0.0 || n > 86400.0 {
        return Err("seconds must be > 0 and <= 86400".into());
    }
    let d = Duration::from_secs_f64(n);
    if d < Duration::from_micros(1) {
        return Err("minimum interval/duration is 0.000001 seconds".into());
    }
    Ok(d)
}

pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Options, String> {
    let mut o = Options {
        mode: Mode::Icmp,
        server: false,
        window: false,
        mtu: false,
        mss: false,
        tcp_port: None,
        bench: false,
        flood: false,
        v6: false,
        host: None,
        port: 11111,
        count: None,
        interval: Duration::from_secs(1),
        timeout: Duration::from_secs(1),
        duration: None,
        size: 64,
    };
    let mut args = args.into_iter();
    let (mut mode, mut pacing, mut family, mut client_flags, mut port_set) =
        (false, false, false, false, false);
    let mut size_set = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-u" | "-t" | "-C" => {
                if mode {
                    return Err("-u, -t and -C are mutually exclusive".into());
                }
                mode = true;
                client_flags = true;
                o.mode = match arg.as_str() {
                    "-u" => Mode::Udp,
                    "-t" => Mode::Tcp,
                    _ => Mode::Connect,
                };
            }
            "-s" => o.server = true,
            "-S" => {
                o.mss = true;
                client_flags = true;
            }
            "-M" => {
                o.mtu = true;
                client_flags = true;
            }
            "-w" => {
                o.window = true;
                client_flags = true;
            }
            "-b" => {
                o.bench = true;
                client_flags = true;
            }
            "-4" | "-6" => {
                if family {
                    return Err("choose one of -4 or -6".into());
                }
                family = true;
                o.v6 = arg == "-6";
            }
            "-f" | "-i" | "-r" => {
                if pacing {
                    return Err("-i, -r and -f are mutually exclusive".into());
                }
                pacing = true;
                client_flags = true;
                if arg == "-f" {
                    o.flood = true;
                } else {
                    let value = args
                        .next()
                        .ok_or_else(|| format!("{arg} requires a value"))?;
                    o.interval = if arg == "-i" {
                        seconds(&value)?
                    } else {
                        let rate: f64 = value.parse().map_err(|_| "invalid PPS")?;
                        if !rate.is_finite() || rate <= 0.0 || rate > 1_000_000.0 {
                            return Err("PPS must be > 0 and <= 1000000".into());
                        }
                        seconds(&(1.0 / rate).to_string())?
                    };
                }
            }
            "-p" | "-P" | "-c" | "-W" | "-T" | "-l" => {
                let value = args
                    .next()
                    .ok_or_else(|| format!("{arg} requires a value"))?;
                client_flags |= arg != "-p";
                match arg.as_str() {
                    "-p" => {
                        o.port = value.parse().map_err(|_| "invalid port")?;
                        port_set = true;
                        if o.port == 0 {
                            return Err("port must be 1..65535".into());
                        }
                    }
                    "-P" => {
                        let port = value.parse().map_err(|_| "invalid TCP port")?;
                        if port == 0 {
                            return Err("TCP port must be 1..65535".into());
                        }
                        o.tcp_port = Some(port);
                    }
                    "-c" => {
                        let n = value.parse().map_err(|_| "invalid count")?;
                        if n == 0 {
                            return Err("count must be positive".into());
                        }
                        o.count = Some(n);
                    }
                    "-W" => o.timeout = seconds(&value)?,
                    "-T" => o.duration = Some(seconds(&value)?),
                    _ => {
                        size_set = true;
                        o.size = value.parse().map_err(|_| "invalid payload size")?;
                        if !(32..=65507).contains(&o.size) {
                            return Err("payload size must be 32..65507".into());
                        }
                    }
                }
            }
            x if x.starts_with('-') => return Err(format!("unknown option {x}; use -h")),
            _ => {
                if o.host.replace(arg).is_some() {
                    return Err("specify exactly one target".into());
                }
            }
        }
    }
    if o.mss {
        if o.server
            || o.window
            || o.mtu
            || o.bench
            || pacing
            || size_set
            || o.count.is_some()
            || o.duration.is_some()
            || o.tcp_port.is_some()
            || (mode && o.mode != Mode::Tcp)
        {
            return Err("-S accepts only HOST, -t, -p, -W and -4/-6".into());
        }
        if !mode {
            o.mode = Mode::Connect;
        }
    }
    if o.tcp_port.is_some() && !o.window {
        return Err("-P requires -w".into());
    }
    if o.mtu {
        if o.server || o.window || o.bench || o.flood || !o.mode.datagram() {
            return Err("-M cannot be combined with -t/-C/-s/-w/-b/-f".into());
        }
        if !size_set {
            o.size = 9000 - if o.v6 { 48 } else { 28 };
        }
        if !pacing {
            o.interval = Duration::from_millis(100);
        }
        if o.duration.is_none() {
            o.duration = Some(Duration::from_secs(60));
        }
    }
    if o.window && (o.server || o.bench || o.flood || matches!(o.mode, Mode::Udp | Mode::Tcp)) {
        return Err("-w cannot be combined with -u/-t/-s/-b/-f".into());
    }
    if o.server {
        if client_flags || o.host.is_some() {
            return Err("server accepts only -s, -p and -4/-6".into());
        }
    } else {
        if o.host.is_none() {
            return Err("target required; use -h".into());
        }
        if port_set && o.mode == Mode::Icmp && !o.window {
            return Err("ICMP does not use ports".into());
        }
        if (o.mode == Mode::Icmp || o.window) && o.size > 65499 {
            return Err("ICMP payload must be <= 65499 bytes".into());
        }
        if o.flood && !o.bench {
            return Err("-f requires -b".into());
        }
        if o.bench {
            if !pacing {
                o.interval = Duration::from_millis(1);
            }
            if o.duration.is_none() {
                o.duration = Some(Duration::from_secs(10));
            }
        }
    }
    Ok(o)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn opts(s: &str) -> Result<Options, String> {
        parse(s.split_whitespace().map(str::to_owned))
    }
    #[test]
    fn mss_is_one_shot_and_paired_queries_are_explicit() {
        let o = opts("-S -p 443 host").unwrap();
        assert!(o.mss);
        assert_eq!(o.mode, Mode::Connect);
        let o = opts("-S -t -6 -W .2 host").unwrap();
        assert_eq!(o.mode, Mode::Tcp);
        assert!(o.v6);
        for flags in [
            "-u", "-C", "-M", "-w", "-s", "-b", "-f", "-i .1", "-r 2", "-c 1", "-T 2", "-l 64",
            "-P 443",
        ] {
            assert!(opts(&format!("-S {flags} host")).is_err(), "{flags}");
        }
    }
    #[test]
    fn defaults_and_modes() {
        let o = opts("host").unwrap();
        assert_eq!(o.mode, Mode::Icmp);
        assert_eq!(o.interval.as_secs(), 1);
        assert!(o.duration.is_none());
        let o = opts("-u -b -c 10 host").unwrap();
        assert_eq!(o.interval.as_micros(), 1000);
        assert_eq!(o.duration.unwrap().as_secs(), 10);
        assert!(opts("-s -6 -p 9999").unwrap().v6);
        assert_eq!(opts("-C -p 443 host").unwrap().mode, Mode::Connect);
        assert_eq!(
            opts("-t -b -r 20 -T .2 host").unwrap().interval.as_millis(),
            50
        );
    }

    #[test]
    fn mtu_limits_preserve_payload_and_global_count_semantics() {
        let o = opts("-M host").unwrap();
        assert!(o.mtu);
        assert_eq!(o.size, 8972);
        assert_eq!(o.interval, Duration::from_millis(100));
        assert_eq!(o.duration, Some(Duration::from_secs(60)));
        assert_eq!(opts("-M -6 host").unwrap().size, 8952);
        let o = opts("-M -u -p 9999 -l 1472 -c 9 -T 2 -i .01 host").unwrap();
        assert_eq!(o.size, 1472);
        assert_eq!(o.count, Some(9));
        assert_eq!(o.duration, Some(Duration::from_secs(2)));
        for flags in ["-t", "-C", "-s", "-w", "-b", "-f"] {
            assert!(opts(&format!("-M {flags} host")).is_err());
        }
    }
    #[test]
    fn invalid_combinations_and_numbers() {
        for s in [
            "",
            "-u -t host",
            "-C -u host",
            "-r 1 -i 1 host",
            "-f host",
            "-s host",
            "-s -b",
            "-p 0 -u host",
            "-c 0 host",
            "-c -1 host",
            "-i NaN host",
            "-r inf host",
            "-r 0 host",
            "-W 0 host",
            "-T -1 host",
            "-l 31 host",
            "-l 65508 host",
            "-4 -6 host",
            "-u host host2",
            "-p 80 host",
            "--udp host",
            "-P 443 host",
            "-w -P 0 host",
            "-w -u host",
            "-w -t host",
            "-w -s",
            "-w -b host",
            "-w -f host",
            "-w -C -l 65507 host",
        ] {
            assert!(opts(s).is_err(), "{s}");
        }
    }
    #[test]
    fn window_options_and_independent_ports() {
        let o = opts("-w -C -P 443 -p 2222 -r 5 -c 7 host").unwrap();
        assert!(o.window);
        assert_eq!(o.mode, Mode::Connect);
        assert_eq!(o.port, 2222);
        assert_eq!(o.tcp_port, Some(443));
        assert_eq!(o.interval, Duration::from_millis(200));
        let o = opts("-w host").unwrap();
        assert_eq!(o.interval, Duration::from_secs(1));
        assert!(o.duration.is_none());
        assert!(opts("-w -p 2222 host").is_ok());
    }
}
