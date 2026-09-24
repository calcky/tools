use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::IpAddr,
    time::{Duration, Instant},
};

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Tuple {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub proto: u8,
    pub sport: Option<u16>,
    pub dport: Option<u16>,
    pub icmp: Option<(u16, u8, u8)>,
}

impl Tuple {
    pub fn reverse(&self) -> Self {
        Self {
            src: self.dst,
            dst: self.src,
            sport: self.dport,
            dport: self.sport,
            ..self.clone()
        }
    }
    pub fn label(&self) -> String {
        let endpoint = |ip: IpAddr, port: Option<u16>| match port {
            Some(port) if ip.is_ipv6() => format!("[{ip}]:{port}"),
            Some(port) => format!("{ip}:{port}"),
            None => ip.to_string(),
        };
        let icmp = self
            .icmp
            .map(|(id, ty, code)| format!(" id={id} type={ty}/{code}"))
            .unwrap_or_default();
        format!(
            "{} {} -> {}{icmp}",
            protocol(self.proto),
            endpoint(self.src, self.sport),
            endpoint(self.dst, self.dport)
        )
    }
}

pub fn protocol(value: u8) -> String {
    match value {
        6 => "tcp".into(),
        17 => "udp".into(),
        1 => "icmp".into(),
        58 => "icmp6".into(),
        132 => "sctp".into(),
        n => n.to_string(),
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Key {
    pub original: Tuple,
    pub zone: u16,
    pub reply_zone: u16,
}

#[derive(Clone, Debug)]
pub struct TrafficSample {
    pub at: Instant,
    pub bytes: [Option<u64>; 2],
    pub bytes_per_second: [Option<f64>; 2],
}

#[derive(Clone, Debug)]
pub struct Entry {
    pub key: Key,
    pub reply: Option<Tuple>,
    pub id: Option<u32>,
    pub status: Option<u32>,
    pub state: Option<u8>,
    pub timeout: Option<u32>,
    pub mark: Option<u32>,
    pub packets: [Option<u64>; 2],
    pub bytes: [Option<u64>; 2],
    pub traffic: Option<TrafficSample>,
    pub start_ns: Option<u64>,
    pub seen: Instant,
    pub state_since: Instant,
}

impl Entry {
    pub fn mark_label(&self) -> String {
        self.mark
            .map_or_else(|| "N/A".into(), |mark| format!("0x{mark:x}"))
    }
    pub fn sample_traffic(&mut self, old: Option<&Self>, at: Instant) {
        let previous = old
            .filter(|old| {
                old.same_generation(self)
                    && (old.id.zip(self.id).is_some_and(|(a, b)| a == b)
                        || old.start_ns.zip(self.start_ns).is_some_and(|(a, b)| a == b))
            })
            .and_then(|old| old.traffic.as_ref());
        let bytes_per_second = std::array::from_fn(|i| {
            let old = previous?;
            let seconds = at.checked_duration_since(old.at)?.as_secs_f64();
            if seconds <= 0.0 {
                return None;
            }
            Some(self.bytes[i]?.checked_sub(old.bytes[i]?)? as f64 / seconds)
        });
        self.traffic = Some(TrafficSample {
            at,
            bytes: self.bytes,
            bytes_per_second,
        });
    }
    pub fn tuple(&self, nat: bool) -> Tuple {
        if nat {
            self.reply
                .as_ref()
                .map(Tuple::reverse)
                .unwrap_or_else(|| self.key.original.clone())
        } else {
            self.key.original.clone()
        }
    }
    pub fn is_nat(&self) -> bool {
        self.status.is_some_and(|s| s & ((1 << 4) | (1 << 5)) != 0)
    }
    pub fn unreplied(&self) -> bool {
        self.status.is_some_and(|s| s & (1 << 1) == 0)
    }
    pub fn state_label(&self) -> &'static str {
        if self.key.original.proto != 6 {
            return if self.unreplied() {
                "UNREPLIED"
            } else if self.status.is_some() {
                "REPLIED"
            } else {
                "UNKNOWN"
            };
        }
        match self.state {
            Some(1) => "SYN_SENT",
            Some(2) => "SYN_RECV",
            Some(3) => "ESTABLISHED",
            Some(4) => "FIN_WAIT",
            Some(5) => "CLOSE_WAIT",
            Some(6) => "LAST_ACK",
            Some(7) => "TIME_WAIT",
            Some(8) => "CLOSE",
            Some(9) => "SYN_SENT2",
            _ => "UNKNOWN",
        }
    }
    pub fn same_generation(&self, other: &Self) -> bool {
        self.key == other.key
            && match (self.id, other.id) {
                (Some(a), Some(b)) => a == b,
                _ => true,
            }
    }
    pub fn merge(&mut self, patch: Self, now: Instant) {
        if patch.state.is_some() && patch.state != self.state {
            self.state_since = now;
        }
        if patch.reply.is_some() {
            self.reply = patch.reply;
        }
        if patch.id.is_some() {
            self.id = patch.id;
        }
        if patch.status.is_some() {
            self.status = patch.status;
        }
        if patch.state.is_some() {
            self.state = patch.state;
        }
        if patch.timeout.is_some() {
            self.timeout = patch.timeout;
        }
        if patch.mark.is_some() {
            self.mark = patch.mark;
        }
        if patch.start_ns.is_some() {
            self.start_ns = patch.start_ns;
        }
        for i in 0..2 {
            if let Some(n) = patch.packets[i] {
                self.packets[i] = Some(self.packets[i].unwrap_or(0).max(n));
            }
            if let Some(n) = patch.bytes[i] {
                self.bytes[i] = Some(self.bytes[i].unwrap_or(0).max(n));
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    Src,
    Sport,
    Dst,
    Dport,
    Proto,
    Zone,
    Mark,
}
impl Field {
    pub fn parse(text: &str) -> Result<Vec<Self>, String> {
        let mut fields = Vec::new();
        for word in text.split(',') {
            let field = match word.trim() {
                "src" => Self::Src,
                "sport" => Self::Sport,
                "dst" => Self::Dst,
                "dport" => Self::Dport,
                "proto" => Self::Proto,
                "zone" => Self::Zone,
                "mark" => Self::Mark,
                _ => return Err("group fields: src,sport,dst,dport,proto,zone,mark".into()),
            };
            if fields.contains(&field) {
                return Err("duplicate group field".into());
            }
            fields.push(field);
        }
        Ok(fields)
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Src => "src",
            Self::Sport => "sport",
            Self::Dst => "dst",
            Self::Dport => "dport",
            Self::Proto => "proto",
            Self::Zone => "zone",
            Self::Mark => "mark",
        }
    }
}

pub fn group_key(entry: &Entry, fields: &[Field], nat: bool) -> String {
    group_values(entry, fields, nat).join(" | ")
}

fn group_values(entry: &Entry, fields: &[Field], nat: bool) -> Vec<String> {
    let t = entry.tuple(nat);
    let mut values: Vec<_> = fields
        .iter()
        .map(|field| match field {
            Field::Src => t.src.to_string(),
            Field::Dst => t.dst.to_string(),
            Field::Sport => t.sport.map_or_else(|| "-".into(), |n| n.to_string()),
            Field::Dport => t.dport.map_or_else(|| "-".into(), |n| n.to_string()),
            Field::Proto => protocol(t.proto),
            Field::Zone => format!("{}/{}", entry.key.zone, entry.key.reply_zone),
            Field::Mark => entry.mark_label(),
        })
        .collect();
    // Zones are always separate, including when the user omits the zone column.
    if !fields.contains(&Field::Zone) && (entry.key.zone != 0 || entry.key.reply_zone != 0) {
        values.push(format!("z={}/{}", entry.key.zone, entry.key.reply_zone));
    }
    if nat && entry.reply.is_none() {
        values.push("NAT unknown".into());
    }
    values
}

#[derive(Clone, Default)]
pub struct Filter {
    pub src: Option<IpAddr>,
    pub dst: Option<IpAddr>,
    pub sport: Option<u16>,
    pub dport: Option<u16>,
    pub proto: Option<u8>,
    pub zone: Option<u16>,
}
impl Filter {
    pub fn matches(&self, e: &Entry) -> bool {
        let t = &e.key.original;
        self.src.is_none_or(|v| v == t.src)
            && self.dst.is_none_or(|v| v == t.dst)
            && self.sport.is_none_or(|v| Some(v) == t.sport)
            && self.dport.is_none_or(|v| Some(v) == t.dport)
            && self.proto.is_none_or(|v| v == t.proto)
            && self.zone.is_none_or(|v| v == e.key.zone)
    }
}

#[derive(Default, Clone)]
pub struct Group {
    pub key: String,
    pub values: Vec<String>,
    pub sessions: u64,
    pub new: u64,
    pub end: u64,
    pub unreplied: u64,
    pub syn: u64,
    pub established: u64,
    pub closing: u64,
    pub nat: u64,
    pub old_syn: u64,
    pub old_unreplied: u64,
    pub old_closing: u64,
    pub bytes: [u128; 2],
    pub accounted: [u64; 2],
    pub packets: [u128; 2],
    pub packets_accounted: [u64; 2],
    pub bandwidth: [f64; 2],
    pub bandwidth_accounted: [u64; 2],
    pub states: BTreeMap<&'static str, u64>,
    pub protocols: BTreeMap<String, u64>,
    pub destinations: HashSet<IpAddr>,
    pub destination_ports: HashSet<(u8, u16)>,
    pub source_group: bool,
}
impl Group {
    pub fn flags(&self) -> String {
        let mut flags = Vec::new();
        if self.old_syn > 0 {
            flags.push(format!("SYN-aged:{}", self.old_syn));
        }
        if self.old_unreplied > 0 {
            flags.push(format!("unreplied-aged:{}", self.old_unreplied));
        }
        if self.old_closing > 0 {
            flags.push(format!("closing-aged:{}", self.old_closing));
        }
        if self.source_group
            && (self.destinations.len() >= 128 || self.destination_ports.len() >= 128)
        {
            flags.push(format!(
                "fanout:{}/{}",
                self.destinations.len(),
                self.destination_ports.len()
            ));
        }
        if flags.is_empty() {
            "-".into()
        } else {
            flags.join(" ")
        }
    }
    fn add(&mut self, entry: &Entry, now: Instant, threshold: Duration, nat: bool) {
        let tuple = entry.tuple(nat);
        self.destinations.insert(tuple.dst);
        if let Some(port) = tuple.dport {
            self.destination_ports.insert((tuple.proto, port));
        }
        *self.protocols.entry(protocol(tuple.proto)).or_default() += 1;
        self.sessions += 1;
        self.unreplied += u64::from(entry.unreplied());
        self.nat += u64::from(entry.is_nat());
        let tcp = entry.key.original.proto == 6;
        let syn = tcp && matches!(entry.state, Some(1 | 2 | 9));
        let closing = tcp && matches!(entry.state, Some(4..=8));
        self.syn += u64::from(syn);
        self.established += u64::from(tcp && entry.state == Some(3));
        self.closing += u64::from(closing);
        let old = now.saturating_duration_since(entry.state_since) >= threshold;
        self.old_syn += u64::from(syn && old);
        self.old_unreplied +=
            u64::from(entry.unreplied() && now.saturating_duration_since(entry.seen) >= threshold);
        self.old_closing += u64::from(closing && old);
        *self.states.entry(entry.state_label()).or_default() += 1;
        for i in 0..2 {
            if let Some(packets) = entry.packets[i] {
                self.packets[i] += packets as u128;
                self.packets_accounted[i] += 1;
            }
            if let Some(rate) = entry.traffic.as_ref().and_then(|s| s.bytes_per_second[i]) {
                self.bandwidth[i] += rate;
                self.bandwidth_accounted[i] += 1;
            }
            if let Some(bytes) = entry.bytes[i] {
                self.bytes[i] += bytes as u128;
                self.accounted[i] += 1;
            }
        }
    }
}

pub fn aggregate<'a>(
    entries: impl Iterator<Item = &'a Entry>,
    events: impl IntoIterator<Item = &'a (bool, Entry)>,
    fields: &[Field],
    nat: bool,
    filter: &Filter,
    now: Instant,
    threshold: Duration,
) -> Vec<Group> {
    let mut groups: HashMap<String, Group> = HashMap::new();
    for entry in entries.filter(|e| filter.matches(e)) {
        let key = group_key(entry, fields, nat);
        let group = groups.entry(key.clone()).or_insert_with(|| Group {
            key,
            values: group_values(entry, fields, nat),
            ..Group::default()
        });
        group.source_group = fields.contains(&Field::Src);
        group.add(entry, now, threshold, nat);
    }
    for (new, entry) in events.into_iter().filter(|(_, e)| filter.matches(e)) {
        let key = group_key(entry, fields, nat);
        let group = groups.entry(key.clone()).or_insert_with(|| Group {
            key,
            values: group_values(entry, fields, nat),
            ..Group::default()
        });
        if *new {
            group.new += 1;
        } else {
            group.end += 1;
        }
    }
    groups.into_values().collect()
}

#[cfg(test)]
pub fn fixture() -> Entry {
    let now = Instant::now();
    let t = Tuple {
        src: "192.0.2.1".parse().unwrap(),
        dst: "198.51.100.2".parse().unwrap(),
        proto: 6,
        sport: Some(1234),
        dport: Some(443),
        icmp: None,
    };
    Entry {
        key: Key {
            original: t.clone(),
            zone: 0,
            reply_zone: 0,
        },
        reply: Some(t.reverse()),
        id: Some(1),
        status: Some(2),
        state: Some(3),
        timeout: Some(120),
        mark: Some(0),
        packets: [Some(10); 2],
        bytes: [Some(100); 2],
        traffic: None,
        start_ns: None,
        seen: now,
        state_since: now,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mark_groups_distinguish_zero_unknown_and_combined_fields() {
        let entries = [None, Some(0), Some(16), Some(u32::MAX)].map(|mark| {
            let mut e = fixture();
            e.mark = mark;
            e
        });
        assert_eq!(
            Field::parse("mark,proto").unwrap(),
            vec![Field::Mark, Field::Proto]
        );
        assert_eq!(Field::Mark.name(), "mark");
        let groups = aggregate(
            entries.iter(),
            &[],
            &[Field::Mark],
            false,
            &Filter::default(),
            Instant::now(),
            Duration::from_secs(10),
        );
        assert_eq!(groups.len(), 4);
        for key in ["N/A", "0x0", "0x10", "0xffffffff"] {
            assert!(groups.iter().any(|g| g.key == key && g.sessions == 1));
        }
        assert_eq!(
            group_key(&entries[2], &[Field::Mark, Field::Proto], true),
            "0x10 | tcp"
        );
        let mut e = entries[2].clone();
        let mut patch = e.clone();
        patch.mark = None;
        e.merge(patch.clone(), Instant::now());
        assert_eq!(e.mark, Some(16));
        patch.mark = Some(0);
        e.merge(patch, Instant::now());
        assert_eq!(e.mark_label(), "0x0");
    }
    #[test]
    fn bandwidth_requires_two_samples_and_matching_generation() {
        let at = Instant::now();
        let mut first = fixture();
        first.sample_traffic(None, at);
        assert_eq!(first.traffic.as_ref().unwrap().bytes_per_second, [None; 2]);
        let mut next = first.clone();
        next.bytes = [Some(1100), Some(2100)];
        next.sample_traffic(Some(&first), at + Duration::from_secs(2));
        assert_eq!(
            next.traffic.as_ref().unwrap().bytes_per_second,
            [Some(500.0), Some(1000.0)]
        );
        next.bytes = [Some(50), None];
        next.sample_traffic(Some(&first), at + Duration::from_secs(2));
        assert_eq!(next.traffic.as_ref().unwrap().bytes_per_second, [None; 2]);
        next.bytes = [Some(1100); 2];
        next.id = Some(2);
        next.sample_traffic(Some(&first), at + Duration::from_secs(2));
        assert_eq!(next.traffic.as_ref().unwrap().bytes_per_second, [None; 2]);
        first.id = None;
        next.id = None;
        next.sample_traffic(Some(&first), at + Duration::from_secs(2));
        assert_eq!(next.traffic.as_ref().unwrap().bytes_per_second, [None; 2]);
    }
    #[test]
    fn traffic_aggregation_preserves_partial_coverage_and_large_packet_totals() {
        let at = Instant::now();
        let mut a = fixture();
        a.sample_traffic(None, at);
        let mut next = a.clone();
        next.bytes = [Some(1100); 2];
        next.packets = [Some(u64::MAX), None];
        next.sample_traffic(Some(&a), at + Duration::from_secs(2));
        a.packets = [Some(u64::MAX), Some(2)];
        let rows = aggregate(
            [&a, &next].into_iter(),
            &[],
            &[Field::Src],
            false,
            &Filter::default(),
            at,
            Duration::from_secs(10),
        );
        let g = &rows[0];
        assert_eq!(g.packets, [2 * u64::MAX as u128, 2]);
        assert_eq!(g.packets_accounted, [2, 1]);
        assert_eq!(g.bandwidth, [500.0; 2]);
        assert_eq!(g.bandwidth_accounted, [1; 2]);
    }
    #[test]
    fn nat_is_reversed_reply_and_zones_stay_separate() {
        let mut e = fixture();
        e.reply.as_mut().unwrap().dst = "203.0.113.1".parse().unwrap();
        e.reply.as_mut().unwrap().dport = Some(5000);
        assert_eq!(
            group_key(&e, &[Field::Src, Field::Sport], true),
            "203.0.113.1 | 5000"
        );
        assert_eq!(group_key(&e, &[Field::Src], false), "192.0.2.1");
        e.key.zone = 2;
        assert!(group_key(&e, &[Field::Src], false).ends_with("z=2/0"));
    }
    #[test]
    fn state_age_is_observed_not_remaining_timeout() {
        let mut e = fixture();
        e.state = Some(1);
        e.status = Some(0);
        e.timeout = Some(1);
        let rows = aggregate(
            [&e].into_iter(),
            &[],
            &[Field::Src],
            false,
            &Filter::default(),
            e.seen + Duration::from_secs(5),
            Duration::from_secs(10),
        );
        assert_eq!(rows[0].old_syn, 0);
        let rows = aggregate(
            [&e].into_iter(),
            &[],
            &[Field::Src],
            false,
            &Filter::default(),
            e.seen + Duration::from_secs(11),
            Duration::from_secs(10),
        );
        assert_eq!(rows[0].old_syn, 1);
        assert_eq!(rows[0].unreplied, 1);
    }
    #[test]
    fn partial_updates_preserve_counters_and_reset_state_age() {
        let mut e = fixture();
        let since = e.state_since;
        let mut p = e.clone();
        p.bytes = [None, Some(50)];
        p.state = Some(4);
        e.merge(p, since + Duration::from_secs(2));
        assert_eq!(e.bytes, [Some(100); 2]);
        assert_eq!(e.state_since, since + Duration::from_secs(2));
    }
    #[test]
    fn fanout_is_current_membership_and_only_marks_source_groups() {
        let entries: Vec<_> = (1..=128)
            .map(|port| {
                let mut e = fixture();
                e.key.original.dport = Some(port);
                e
            })
            .collect();
        let groups = aggregate(
            entries.iter(),
            &[],
            &[Field::Src],
            false,
            &Filter::default(),
            Instant::now(),
            Duration::from_secs(10),
        );
        assert_eq!(groups[0].destinations.len(), 1);
        assert_eq!(groups[0].destination_ports.len(), 128);
        assert_eq!(groups[0].protocols["tcp"], 128);
        assert!(groups[0].flags().contains("fanout:1/128"));
        let groups = aggregate(
            entries.iter(),
            &[],
            &[Field::Proto],
            false,
            &Filter::default(),
            Instant::now(),
            Duration::from_secs(10),
        );
        assert!(!groups[0].flags().contains("fanout"));
    }
    #[test]
    fn protocol_and_zone_partitioning_preserve_totals() {
        let a = fixture();
        let mut b = a.clone();
        b.key.original.proto = 17;
        b.state = None;
        let mut c = a.clone();
        c.key.reply_zone = 5;
        let groups = aggregate(
            [&a, &b, &c].into_iter(),
            &[(true, a.clone()), (false, b.clone())],
            &[Field::Src, Field::Proto],
            false,
            &Filter::default(),
            Instant::now(),
            Duration::from_secs(10),
        );
        assert_eq!(groups.len(), 3);
        assert_eq!(groups.iter().map(|g| g.sessions).sum::<u64>(), 3);
        assert_eq!(groups.iter().map(|g| g.new).sum::<u64>(), 1);
        assert_eq!(groups.iter().map(|g| g.end).sum::<u64>(), 1);
    }
    #[test]
    fn filters_keep_original_semantics_and_no_port_is_not_zero() {
        let mut e = fixture();
        e.key.original.proto = 1;
        e.key.original.sport = None;
        assert!(!Filter {
            sport: Some(0),
            ..Filter::default()
        }
        .matches(&e));
        assert!(Field::parse("src,dport,proto").is_ok());
        assert!(Field::parse("src,src").is_err());
        assert!(Field::parse("").is_err());
    }
}
