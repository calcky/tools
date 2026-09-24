use std::fmt;
use std::net::IpAddr;

use ipnet::IpNet;

mod expression;
#[cfg(test)]
mod expression_tests;
use expression::Expression;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Side {
    Any,
    Source,
    Destination,
}

#[derive(Clone, Eq, PartialEq)]
enum Term {
    Host(Side, IpNet),
    Port(Side, u16),
    Protocol(u8),
}

pub(crate) type Endpoint = (IpAddr, Option<u16>);

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct ConnectionFilter {
    query: String,
    terms: Vec<Term>,
    expression: Option<Expression>,
}

impl fmt::Debug for ConnectionFilter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectionFilter")
            .field("term_count", &self.terms.len())
            .field(
                "expression_nodes",
                &self.expression.as_ref().map(Expression::len),
            )
            .finish()
    }
}

impl ConnectionFilter {
    pub(crate) fn parse(query: &str) -> Result<Option<Self>, &'static str> {
        if query.len() > 512 {
            return Err("filter must be at most 512 bytes");
        }
        let query = query.trim();
        if query.is_empty() {
            return Ok(None);
        }
        if expression::is_expression(query) {
            if query.contains('=') {
                return Err("do not mix key=value filters with expressions");
            }
            return Ok(Some(Self {
                query: query.to_owned(),
                terms: Vec::new(),
                expression: Some(Expression::parse(query)?),
            }));
        }
        let mut terms = Vec::new();
        for token in query.split_ascii_whitespace() {
            if terms.len() == 8 {
                return Err("filter accepts at most 8 terms");
            }
            let term = if let Some((key, value)) = token.split_once('=') {
                match key {
                    "host" => Term::Host(Side::Any, host(value)?),
                    "src" => Term::Host(Side::Source, host(value)?),
                    "dst" => Term::Host(Side::Destination, host(value)?),
                    "port" => Term::Port(Side::Any, port(value)?),
                    "sport" => Term::Port(Side::Source, port(value)?),
                    "dport" => Term::Port(Side::Destination, port(value)?),
                    "proto" => Term::Protocol(protocol(value)?),
                    _ => return Err("use host, src, dst, port, sport, dport or proto"),
                }
            } else if let Ok(network) = host(token) {
                Term::Host(Side::Any, network)
            } else if let Ok(port) = token.parse::<u16>() {
                Term::Port(Side::Any, port)
            } else {
                Term::Protocol(protocol(token)?)
            };
            terms.push(term);
        }
        Ok(Some(Self {
            query: query.to_owned(),
            terms,
            expression: None,
        }))
    }

    pub(crate) fn parse_socket(query: &str) -> Result<Option<Self>, &'static str> {
        let parsed = Self::parse(query)?;
        if parsed.as_ref().is_some_and(|filter| {
            filter
                .terms
                .iter()
                .any(|term| matches!(term, Term::Protocol(p) if !matches!(p, 6 | 17)))
        }) {
            return Err("socket protocol must be tcp, udp, 6 or 17");
        }
        Ok(parsed)
    }

    pub(crate) fn query(&self) -> &str {
        &self.query
    }

    pub(crate) fn matches(
        &self,
        protocol: u8,
        source: Endpoint,
        destination: Endpoint,
        endpoints: &[Endpoint],
    ) -> bool {
        if let Some(expression) = &self.expression {
            return expression.matches(protocol, source, destination);
        }
        self.terms.iter().all(|term| {
            let select = |side| match side {
                Side::Any => endpoints,
                Side::Source => std::slice::from_ref(&source),
                Side::Destination => std::slice::from_ref(&destination),
            };
            match term {
                Term::Host(side, network) => {
                    select(*side).iter().any(|(ip, _)| network.contains(ip))
                }
                Term::Port(side, port) => select(*side).iter().any(|(_, p)| *p == Some(*port)),
                Term::Protocol(p) => *p == protocol,
            }
        })
    }

    #[cfg(test)]
    pub(crate) fn from_fields(
        host: &str,
        port: &str,
        protocol: &str,
    ) -> Result<Option<Self>, &'static str> {
        if host.len() > 128 || port.len() > 16 || protocol.len() > 32 {
            return Err("flow filter field is too long");
        }
        let mut fields = Vec::new();
        for (key, value) in [
            ("host", host.trim()),
            ("port", port.trim()),
            ("proto", protocol.trim()),
        ] {
            if value.chars().any(char::is_whitespace) {
                return Err("each field accepts one value");
            }
            if !value.is_empty() && !(key == "proto" && value.eq_ignore_ascii_case("all")) {
                fields.push(format!("{key}={value}"));
            }
        }
        Self::parse(&fields.join(" "))
    }
}

fn host(value: &str) -> Result<IpNet, &'static str> {
    let (address, prefix) = value
        .split_once('/')
        .map_or((value, None), |(a, p)| (a, Some(p)));
    let address: IpAddr = address
        .strip_prefix('[')
        .and_then(|a| a.strip_suffix(']'))
        .unwrap_or(address)
        .parse()
        .map_err(|_| "host must be an IPv4/IPv6 address or CIDR")?;
    match prefix {
        Some(prefix) => IpNet::new(address, prefix.parse().map_err(|_| "invalid CIDR prefix")?)
            .map(|network| network.trunc())
            .map_err(|_| "invalid CIDR prefix"),
        None => Ok(IpNet::from(address)),
    }
}

fn port(value: &str) -> Result<u16, &'static str> {
    value.parse().map_err(|_| "port must be 0-65535")
}

fn protocol(value: &str) -> Result<u8, &'static str> {
    match value.to_ascii_lowercase().as_str() {
        "tcp" => Ok(6),
        "udp" => Ok(17),
        "icmp" => Ok(1),
        "icmp6" | "icmpv6" | "ipv6-icmp" => Ok(58),
        "sctp" => Ok(132),
        "gre" => Ok(47),
        _ => value
            .parse()
            .map_err(|_| "protocol must be tcp, udp, icmp, icmpv6, sctp, gre or 0-255"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(ip: &str, port: Option<u16>) -> Endpoint {
        (ip.parse().unwrap(), port)
    }

    #[test]
    fn cidr_boundaries_families_and_normalization() {
        for (query, ip, expected) in [
            ("192.0.2.99/24", "192.0.2.0", true),
            ("192.0.2.99/24", "192.0.2.255", true),
            ("192.0.2.99/24", "192.0.3.0", false),
            ("0.0.0.0/0", "255.255.255.255", true),
            ("0.0.0.0/0", "::ffff:192.0.2.1", false),
            ("2001:db8::1/64", "2001:db8::ffff", true),
            ("2001:db8::1/64", "2001:db8:0:1::", false),
            ("[2001:db8::1]/128", "2001:db8::1", true),
            ("2001:db8::1", "2001:db8::2", false),
            ("::/0", "::1", true),
        ] {
            let source = endpoint(ip, None);
            let filter = ConnectionFilter::parse(query).unwrap().unwrap();
            assert_eq!(
                filter.matches(1, source, source, &[source]),
                expected,
                "{query} {ip}"
            );
        }
    }

    #[test]
    fn qualified_terms_use_original_direction_and_unqualified_terms_include_nat() {
        let source = endpoint("192.0.2.10", Some(12345));
        let destination = endpoint("198.51.100.2", Some(443));
        let translated = endpoint("10.0.0.2", Some(8443));
        for (query, expected) in [
            (
                "src=192.0.2.0/24 sport=12345 dst=198.51.100.0/24 dport=443 proto=tcp",
                true,
            ),
            ("host=10.0.0.0/8 port=8443 proto=6", true),
            ("dst=10.0.0.0/8", false),
            ("dport=8443", false),
            ("src=198.51.100.2", false),
            ("sport=443", false),
            ("proto=udp", false),
        ] {
            let filter = ConnectionFilter::parse(query).unwrap().unwrap();
            assert_eq!(
                filter.matches(6, source, destination, &[source, destination, translated]),
                expected,
                "{query}"
            );
        }
        let no_port = endpoint("192.0.2.10", None);
        assert!(
            !ConnectionFilter::parse("port=0").unwrap().unwrap().matches(
                1,
                no_port,
                no_port,
                &[no_port]
            )
        );
    }

    #[test]
    fn invalid_input_is_rejected_without_disclosing_addresses_in_debug() {
        for query in [
            "host=",
            "src=example.com",
            "src=1.2.3.4/33",
            "dst=::/129",
            "::/",
            "::/-1",
            "::/64/2",
            "port=65536",
            "sport=-1",
            "dport=abc",
            "proto=256",
            "pid=1",
            "tcp udp tcp udp tcp udp tcp udp tcp",
        ] {
            assert!(ConnectionFilter::parse(query).is_err(), "{query}");
        }
        assert!(ConnectionFilter::parse(&"x".repeat(513)).is_err());
        assert!(ConnectionFilter::parse("  ").unwrap().is_none());
        assert!(ConnectionFilter::parse_socket("proto=icmp").is_err());
        assert!(ConnectionFilter::parse_socket("proto=17 src=::/0").is_ok());
        assert!(ConnectionFilter::from_fields("192.0.2.1 port=22", "", "").is_err());
        let filter = ConnectionFilter::parse("host=192.0.2.1/24 port=8443").unwrap();
        let debug = format!("{filter:?}");
        assert!(!debug.contains("192.0.2"));
        assert!(!debug.contains("8443"));
    }
}
