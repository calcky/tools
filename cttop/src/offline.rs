use crate::{
    engine::{Engine, MAX_ENTRIES},
    model::{Entry, Key, Tuple},
};
use std::{
    collections::HashMap,
    io::{BufRead, Read},
    net::IpAddr,
    time::Instant,
};

pub fn load(mut reader: impl BufRead, source: String) -> Result<Engine, String> {
    let at = Instant::now();
    let mut entries = HashMap::new();
    let mut line = String::new();
    let mut number = 0;
    loop {
        line.clear();
        let read = (&mut reader)
            .take(16_385)
            .read_line(&mut line)
            .map_err(|e| format!("{source}: {}: {e}", number + 1))?;
        if read == 0 {
            break;
        }
        number += 1;
        if read > 16_384 {
            return Err(format!("{source}:{number}: line exceeds 16 KiB"));
        }
        let entry = parse_line(&line, at).map_err(|e| format!("{source}:{number}: {e}"))?;
        if let Some(entry) = entry {
            if entries.len() >= MAX_ENTRIES {
                return Err(format!("{source}:{number}: exceeds {MAX_ENTRIES} entries"));
            }
            if entries.insert(entry.key.clone(), entry).is_some() {
                return Err(format!(
                    "{source}:{number}: duplicate connection; expected a single snapshot"
                ));
            }
        }
    }
    Ok(Engine::offline(entries, source, at))
}

fn number<T: TryFrom<u64>>(value: &str) -> Result<T, String> {
    let n = if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16)
    } else {
        value.parse()
    }
    .map_err(|_| format!("invalid number {value}"))?;
    T::try_from(n).map_err(|_| format!("number out of range: {value}"))
}

#[derive(Default)]
struct Direction {
    src: Option<IpAddr>,
    dst: Option<IpAddr>,
    sport: Option<u16>,
    dport: Option<u16>,
    id: Option<u16>,
    ty: Option<u8>,
    code: Option<u8>,
    packets: Option<u64>,
    bytes: Option<u64>,
}
fn set<T>(slot: &mut Option<T>, value: T, key: &str) -> Result<(), String> {
    if slot.replace(value).is_some() {
        Err(format!("duplicate {key}"))
    } else {
        Ok(())
    }
}
impl Direction {
    fn tuple(&self, proto: u8) -> Result<Tuple, String> {
        let src = self.src.ok_or("missing src")?;
        let dst = self.dst.ok_or("missing dst")?;
        if src.is_ipv4() != dst.is_ipv4() {
            return Err("mixed address families in tuple".into());
        }
        if matches!(proto, 6 | 17 | 33 | 132 | 136)
            && (self.sport.is_none() || self.dport.is_none())
        {
            return Err("missing sport/dport".into());
        }
        let icmp = if matches!(proto, 1 | 58) {
            if (proto == 1) != src.is_ipv4() {
                return Err("ICMP address family mismatch".into());
            }
            Some((
                self.id.ok_or("missing ICMP id")?,
                self.ty.ok_or("missing ICMP type")?,
                self.code.ok_or("missing ICMP code")?,
            ))
        } else {
            None
        };
        Ok(Tuple {
            src,
            dst,
            proto,
            sport: self.sport,
            dport: self.dport,
            icmp,
        })
    }
}

fn parse_line(line: &str, at: Instant) -> Result<Option<Entry>, String> {
    let line = line.trim();
    if line.is_empty()
        || line.starts_with('#')
        || (line.starts_with("conntrack v") && line.ends_with("flow entries have been shown."))
    {
        return Ok(None);
    }
    if line.chars().any(|c| c.is_control() && c != '\t') {
        return Err("unexpected control character".into());
    }
    let tokens = line.split_whitespace().collect::<Vec<_>>();
    let offset = usize::from(matches!(tokens[0], "ipv4" | "ipv6")) * 2;
    let header = tokens
        .get(offset..offset + 3)
        .ok_or("missing protocol/number/timeout header")?;
    let proto: u8 = number(header[1])?;
    let expected = match header[0] {
        "tcp" => 6,
        "udp" => 17,
        "icmp" => 1,
        "icmpv6" | "icmp6" => 58,
        "sctp" => 132,
        "dccp" => 33,
        "udplite" => 136,
        _ => return Err(format!("unsupported protocol {}", header[0])),
    };
    if proto != expected {
        return Err("protocol name/number mismatch".into());
    }
    let timeout = Some(number(header[2])?);
    let mut directions = [Direction::default(), Direction::default()];
    let mut seen_sources: usize = 0;
    let mut state = None;
    let mut status = 1 << 1;
    let (mut mark, mut id, mut zone, mut orig_zone, mut reply_zone) =
        (None, None, None, None, None);
    for token in &tokens[offset + 3..] {
        if *token == "[UNREPLIED]" {
            status &= !(1 << 1);
            continue;
        }
        if *token == "[ASSURED]" {
            status |= 1 << 2;
            continue;
        }
        let Some((key, value)) = token.split_once('=') else {
            let tcp_state = match *token {
                "SYN_SENT" => Some(1),
                "SYN_RECV" => Some(2),
                "ESTABLISHED" => Some(3),
                "FIN_WAIT" => Some(4),
                "CLOSE_WAIT" => Some(5),
                "LAST_ACK" => Some(6),
                "TIME_WAIT" => Some(7),
                "CLOSE" => Some(8),
                "SYN_SENT2" => Some(9),
                _ => None,
            };
            if proto == 6 && tcp_state.is_some() {
                state = tcp_state;
            }
            continue;
        };
        match key {
            "mark" => {
                set(&mut mark, number(value)?, key)?;
                continue;
            }
            "zone" => {
                set(&mut zone, number(value)?, key)?;
                continue;
            }
            "zone-orig" | "orig-zone" => {
                set(&mut orig_zone, number(value)?, key)?;
                continue;
            }
            "zone-reply" | "reply-zone" => {
                set(&mut reply_zone, number(value)?, key)?;
                continue;
            }
            "id" if !matches!(proto, 1 | 58)
                || (seen_sources == 2 && directions[1].id.is_some()) =>
            {
                set(&mut id, number(value)?, key)?;
                continue;
            }
            _ => (),
        }
        if key == "src" {
            seen_sources += 1;
        }
        if seen_sources > 2 {
            return Err("more than two tuples".into());
        }
        let d = &mut directions[seen_sources.saturating_sub(1)];
        match key {
            "src" => set(
                &mut d.src,
                value.parse().map_err(|_| format!("invalid src {value}"))?,
                key,
            )?,
            "dst" => set(
                &mut d.dst,
                value.parse().map_err(|_| format!("invalid dst {value}"))?,
                key,
            )?,
            "sport" => set(&mut d.sport, number(value)?, key)?,
            "dport" => set(&mut d.dport, number(value)?, key)?,
            "type" => set(&mut d.ty, number(value)?, key)?,
            "code" => set(&mut d.code, number(value)?, key)?,
            "id" => set(&mut d.id, number(value)?, key)?,
            "packets" => set(&mut d.packets, number(value)?, key)?,
            "bytes" => set(&mut d.bytes, number(value)?, key)?,
            _ => (),
        }
    }
    let original = directions[0].tuple(proto)?;
    let reply = directions[1].tuple(proto)?;
    if original.src.is_ipv4() != reply.src.is_ipv4() {
        return Err("mixed original/reply address families".into());
    }
    if offset != 0
        && ((tokens[0] == "ipv4") != original.src.is_ipv4()
            || tokens[1] != if original.src.is_ipv4() { "2" } else { "10" })
    {
        return Err("address family header mismatch".into());
    }
    if original.src != reply.dst || original.sport != reply.dport {
        status |= 1 << 4;
    }
    if original.dst != reply.src || original.dport != reply.sport {
        status |= 1 << 5;
    }
    Ok(Some(Entry {
        key: Key {
            original,
            zone: orig_zone.or(zone).unwrap_or(0),
            reply_zone: reply_zone.or(zone).unwrap_or(0),
        },
        reply: Some(reply),
        id,
        status: Some(status),
        state,
        timeout,
        mark,
        packets: directions.each_ref().map(|d| d.packets),
        bytes: directions.each_ref().map(|d| d.bytes),
        traffic: None,
        start_ns: None,
        seen: at,
        state_since: at,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    const TCP: &str = "tcp 6 431999 ESTABLISHED src=10.0.0.2 dst=198.51.100.2 sport=1234 dport=443 packets=12 bytes=1200 src=198.51.100.2 dst=203.0.113.1 sport=443 dport=40000 packets=8 bytes=800 [ASSURED] mark=16 zone=5 use=1 id=99";
    fn entry(line: &str) -> Entry {
        parse_line(line, Instant::now()).unwrap().unwrap()
    }

    #[test]
    fn tcp_nat_counters_mark_zone_and_extended_header() {
        let e = entry(TCP);
        assert_eq!(e.mark, Some(16));
        assert_eq!(e.id, Some(99));
        assert_eq!((e.key.zone, e.key.reply_zone), (5, 5));
        assert_eq!(e.packets, [Some(12), Some(8)]);
        assert_eq!(e.bytes, [Some(1200), Some(800)]);
        assert_eq!(e.state_label(), "ESTABLISHED");
        assert!(e.is_nat() && !e.unreplied());
        assert_eq!(e.tuple(true).src.to_string(), "203.0.113.1");
        assert_eq!(e.tuple(true).sport, Some(40000));
        let extended = entry(&format!("ipv4 2 {TCP}"));
        assert_eq!(extended.key, e.key);
        let zero = entry(&TCP.replace("mark=16", "mark=0x0"));
        assert_eq!(zero.mark, Some(0));
        let missing = entry(
            &TCP.replace(" mark=16", "")
                .replace(" packets=8 bytes=800", ""),
        );
        assert_eq!(missing.mark, None);
        assert_eq!(missing.packets, [Some(12), None]);
    }

    #[test]
    fn ipv6_udp_icmp_and_directional_zones() {
        let e = entry("ipv6 10 udp 17 29 src=::1 dst=::2 sport=1 dport=53 packets=1 bytes=80 [UNREPLIED] src=::2 dst=::1 sport=53 dport=1 packets=0 bytes=0 mark=0 zone-orig=3 zone-reply=4");
        assert!(e.unreplied() && !e.is_nat());
        assert_eq!(e.bytes[1], Some(0));
        assert_eq!((e.key.zone, e.key.reply_zone), (3, 4));
        let e = entry("icmp 1 29 src=10.0.0.1 dst=10.0.0.2 type=8 code=0 id=42 src=10.0.0.2 dst=10.0.0.1 type=0 code=0 id=42 mark=0 id=1024 use=1");
        assert_eq!(e.key.original.icmp, Some((42, 8, 0)));
        assert_eq!(e.reply.unwrap().icmp, Some((42, 0, 0)));
        assert_eq!(e.id, Some(1024));
        let e = entry("icmpv6 58 29 src=::1 dst=::2 type=128 code=0 id=7 src=::2 dst=::1 type=129 code=0 id=7 mark=0");
        assert_eq!(e.key.original.proto, 58);
        assert!(!e.is_nat());
    }

    #[test]
    fn invalid_and_truncated_records_fail_with_line_number() {
        for bad in [
            "garbage".to_owned(),
            TCP.replace("sport=1234", "sport=65536"),
            TCP.replace("dst=203.0.113.1", "dst=bad"),
            TCP.replace("packets=12", "packets=-1"),
            TCP.replace("tcp 6", "tcp 17"),
            TCP.replace("src=198.51.100.2", "src=::1"),
            TCP.split(" src=198.51.100.2").next().unwrap().to_owned(),
            TCP.replace("mark=16", "mark=1 mark=2"),
            "x".repeat(16_385),
        ] {
            let error = load(format!("# comment\n{bad}\n").as_bytes(), "dump".into())
                .err()
                .unwrap();
            assert!(error.starts_with("dump:2:"), "{error}");
        }
        assert!(load(format!("{TCP}\n{TCP}\n").as_bytes(), "dump".into()).is_err());
    }

    #[test]
    fn offline_engine_never_samples_local_kernel_or_creates_rates() {
        let mut engine = load(
            format!("{TCP}\nconntrack v1.4.8 (conntrack-tools): 1 flow entries have been shown.\n")
                .as_bytes(),
            "dump".into(),
        )
        .unwrap();
        assert_eq!(engine.entries.len(), 1);
        assert_eq!(engine.fd(), -1);
        engine.pump().unwrap();
        assert!(!engine.take_window().1);
        assert_eq!(engine.health.namespace, "dump");
        assert_eq!(engine.health.max, None);
        assert_eq!(engine.health.acct, None);
        assert!(engine.entries.values().all(|e| e.traffic.is_none()));
        assert!(load("\n# empty\n".as_bytes(), "empty".into())
            .unwrap()
            .entries
            .is_empty());
    }
}
