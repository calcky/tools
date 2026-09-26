use crate::model::{Field, Filter};
use std::time::Duration;

pub const HELP: &str = "cttop - read-only conntrack session monitor
Usage: cttop [options]
  -f [FILE]  Load a static conntrack -L dump; omitted FILE or - reads stdin
  -g FIELDS  Group by src,sport,dst,dport,proto,zone,mark (default src); none = one CT per row
  -N         Translated forward/NAT endpoint view (default original)
  -s IP      Original source address filter
  -d IP      Original destination address filter
  -S PORT    Original source port filter
  -D PORT    Original destination port filter
  -p PROTO   tcp,udp,icmp,icmp6,sctp or IP protocol number
  -z ZONE    Original conntrack zone filter
  -i SEC     Refresh/report interval (default 1, minimum 0.2)
  -r SEC     Full snapshot calibration interval (default 5, minimum 1)
  -W SEC     Sustained-state observation threshold (default 10)
  -m N       Minimum live sessions per group (default 0)
  -b         Plain text reports (automatic when stdout is redirected)
  -c N       Stop after N reports; implies -b
  -h         Help
  -v         Version

Keys: 0 connections/groups, 1 src, 2 dst+port+proto, 3 src+dst, 4 proto, 5 sport, 6 dport, 7 mark,
g edit grouping within current scope, n original/NAT, s sort, / search,
Enter drill into group, Esc up/clear, arrows or j/k select, PgUp/PgDn page, [/] detail scroll,
Ctrl+U clears an edit field, h help (h/Esc closes), q/Ctrl+C quit.

Live mode requires CAP_NET_ADMIN; static files need no privileges. Example:
  cttop -f conntrack.txt -g mark
  conntrack -L | cttop -f
  sudo cttop -g dst,dport,proto -p tcp
  sudo ip netns exec router cttop -N
  sudo cttop -b -c 3 -g src,dst

New/s and End/s are observed lifecycle events, not success/failure rates.
Accounting, events and timestamps are never enabled automatically.
NAT changes grouping endpoints; command-line filters always use original tuples.
";

pub struct Options {
    pub input: Option<String>,
    pub fields: Vec<Field>,
    pub nat: bool,
    pub filter: Filter,
    pub interval: Duration,
    pub refresh: Duration,
    pub warning: Duration,
    pub minimum: u64,
    pub batch: bool,
    pub count: Option<usize>,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            input: None,
            fields: vec![Field::Src],
            nat: false,
            filter: Filter::default(),
            interval: Duration::from_secs(1),
            refresh: Duration::from_secs(5),
            warning: Duration::from_secs(10),
            minimum: 0,
            batch: false,
            count: None,
        }
    }
}
pub enum Command {
    Run(Options),
    Help,
    Version,
}
pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Command, String> {
    let mut args = args.into_iter().peekable();
    let mut o = Options::default();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" => return Ok(Command::Help),
            "-v" => return Ok(Command::Version),
            "-N" => o.nat = true,
            "-b" => o.batch = true,
            "-f" => {
                if o.input.is_some() {
                    return Err("-f may only be specified once".into());
                }
                o.input = Some(
                    if args.peek().is_some_and(|s| s == "-" || !s.starts_with('-')) {
                        args.next().unwrap()
                    } else {
                        "-".into()
                    },
                );
            }
            "-g" | "-s" | "-d" | "-S" | "-D" | "-p" | "-z" | "-i" | "-r" | "-W" | "-m" | "-c" => {
                let value = args
                    .next()
                    .ok_or_else(|| format!("{arg} requires a value"))?;
                let bad = || format!("invalid value for {arg}: {value}");
                match arg.as_str() {
                    "-g" => {
                        o.fields = if value == "none" {
                            Vec::new()
                        } else {
                            Field::parse(&value)?
                        }
                    }
                    "-s" => o.filter.src = Some(value.parse().map_err(|_| bad())?),
                    "-d" => o.filter.dst = Some(value.parse().map_err(|_| bad())?),
                    "-S" => o.filter.sport = Some(value.parse().map_err(|_| bad())?),
                    "-D" => o.filter.dport = Some(value.parse().map_err(|_| bad())?),
                    "-z" => o.filter.zone = Some(value.parse().map_err(|_| bad())?),
                    "-m" => o.minimum = value.parse().map_err(|_| bad())?,
                    "-c" => {
                        let n: usize = value.parse().map_err(|_| bad())?;
                        if n == 0 {
                            return Err(bad());
                        }
                        o.count = Some(n);
                        o.batch = true;
                    }
                    "-p" => {
                        o.filter.proto = Some(match value.as_str() {
                            "tcp" => 6,
                            "udp" => 17,
                            "icmp" => 1,
                            "icmp6" => 58,
                            "sctp" => 132,
                            _ => value.parse().map_err(|_| bad())?,
                        })
                    }
                    _ => {
                        let n: f64 = value.parse().map_err(|_| bad())?;
                        let min = if arg == "-i" { 0.2 } else { 1.0 };
                        if !n.is_finite() || !(min..=86400.0).contains(&n) {
                            return Err(bad());
                        }
                        let duration = Duration::from_secs_f64(n);
                        match arg.as_str() {
                            "-i" => o.interval = duration,
                            "-r" => o.refresh = duration,
                            _ => o.warning = duration,
                        }
                    }
                }
            }
            _ => return Err(format!("unknown option {arg}; use -h")),
        }
    }
    Ok(Command::Run(o))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn combinations_and_validation() {
        let run = |s: &str| parse(s.split_whitespace().map(str::to_owned));
        for arg in [
            "-i NaN",
            "-r 0",
            "-c 0",
            "-D 65536",
            "-g src,src",
            "-p 256",
            "-N x",
            "-s nope",
        ] {
            assert!(run(arg).is_err(), "{arg}");
        }
        let Command::Run(o) = run("-g dst,dport,proto -N -p tcp -s ::1 -c 2").unwrap() else {
            panic!()
        };
        assert!(o.nat && o.batch);
        assert_eq!(o.fields.len(), 3);
        assert_eq!(o.filter.proto, Some(6));
        let Command::Run(o) = run("-g none -p udp -D 53 -c 1").unwrap() else {
            panic!()
        };
        assert!(o.fields.is_empty() && o.batch);
        assert_eq!(o.filter.dport, Some(53));
        assert!(run("-g src,none").is_err());
        let Command::Run(o) = run("-g mark,src").unwrap() else {
            panic!()
        };
        assert_eq!(o.fields, vec![Field::Mark, Field::Src]);
        assert!(run("-g mark,mark").is_err());
        for (args, source) in [
            ("-f", "-"),
            ("-f -", "-"),
            ("-f -g mark", "-"),
            ("-f ct.txt -b", "ct.txt"),
        ] {
            let Command::Run(o) = run(args).unwrap() else {
                panic!()
            };
            assert_eq!(o.input.as_deref(), Some(source));
        }
        assert!(run("-f a -f b").is_err());
    }
}
