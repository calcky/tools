use super::{host, port, protocol, Endpoint};
use ipnet::IpNet;
use std::net::{IpAddr, Ipv4Addr};

const MAX_NODES: usize = 64;
const MAX_DEPTH: usize = 16;
const EXPECTED: &str =
    "expected host, net, port, portrange or protocol; packet predicates and DNS are unsupported";

pub(super) fn is_expression(query: &str) -> bool {
    query.split_ascii_whitespace().all(named_protocol)
        || query.contains(['(', ')', '!', '&', '|'])
        || query.split_ascii_whitespace().any(|word| {
            matches!(
                word,
                "host"
                    | "net"
                    | "port"
                    | "portrange"
                    | "src"
                    | "dst"
                    | "and"
                    | "or"
                    | "not"
                    | "ip"
                    | "ip6"
            )
        })
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Direction {
    Either,
    Source,
    Destination,
    Both,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Kind {
    Host,
    Net,
    Port,
    PortRange,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct Qualifier {
    direction: Direction,
    kind: Kind,
    protocol: Option<u8>,
    ipv6: Option<bool>,
}

#[derive(Clone, Eq, PartialEq)]
enum Value {
    Network(IpNet),
    Ports(u16, u16),
}

#[derive(Clone, Eq, PartialEq)]
enum Node {
    Value(Qualifier, Value),
    Protocol(u8),
    Family(bool),
    Not(usize),
    And(usize, usize),
    Or(usize, usize),
}

// No derived Debug: the tree contains private connection addresses and ports.
#[derive(Clone, Eq, PartialEq)]
pub(super) struct Expression {
    nodes: Vec<Node>,
    root: usize,
}

impl Expression {
    pub(super) fn parse(query: &str) -> Result<Self, &'static str> {
        let mut parser = Parser {
            tokens: tokenize(query)?,
            at: 0,
            nodes: Vec::new(),
        };
        let (root, _) = parser.expression(None, 0)?;
        if parser.at != parser.tokens.len() {
            return Err("expected and/or between predicates, or a closing parenthesis");
        }
        Ok(Self {
            nodes: parser.nodes,
            root,
        })
    }

    pub(super) fn len(&self) -> usize {
        self.nodes.len()
    }

    pub(super) fn matches(&self, protocol: u8, source: Endpoint, destination: Endpoint) -> bool {
        self.evaluate(self.root, protocol, source, destination)
    }

    fn evaluate(
        &self,
        index: usize,
        protocol: u8,
        source: Endpoint,
        destination: Endpoint,
    ) -> bool {
        let evaluate = |index| self.evaluate(index, protocol, source, destination);
        match &self.nodes[index] {
            Node::Not(child) => !evaluate(*child),
            Node::And(left, right) => evaluate(*left) && evaluate(*right),
            Node::Or(left, right) => evaluate(*left) || evaluate(*right),
            Node::Protocol(value) => protocol == *value,
            Node::Family(ipv6) => source.0.is_ipv6() == *ipv6 && destination.0.is_ipv6() == *ipv6,
            Node::Value(qualifier, value) => {
                if qualifier.protocol.is_some_and(|p| p != protocol)
                    || qualifier
                        .ipv6
                        .is_some_and(|v6| source.0.is_ipv6() != v6 || destination.0.is_ipv6() != v6)
                {
                    return false;
                }
                let matches = |endpoint: Endpoint| match value {
                    Value::Network(network) => network.contains(&endpoint.0),
                    Value::Ports(low, high) => {
                        matches!(protocol, 6 | 17 | 132)
                            && endpoint.1.is_some_and(|p| (*low..=*high).contains(&p))
                    }
                };
                match qualifier.direction {
                    Direction::Either => matches(source) || matches(destination),
                    Direction::Source => matches(source),
                    Direction::Destination => matches(destination),
                    Direction::Both => matches(source) && matches(destination),
                }
            }
        }
    }
}

fn tokenize(query: &str) -> Result<Vec<&str>, &'static str> {
    let mut tokens = Vec::new();
    let bytes = query.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }
        let start = i;
        match bytes[i] {
            b'(' | b')' | b'!' => i += 1,
            b'&' | b'|' => {
                if bytes.get(i + 1) != Some(&bytes[i]) {
                    return Err("use && or || for logical operators");
                }
                i += 2;
            }
            _ => {
                while i < bytes.len()
                    && !bytes[i].is_ascii_whitespace()
                    && !b"()!&|".contains(&bytes[i])
                {
                    i += 1;
                }
            }
        }
        tokens.push(&query[start..i]);
    }
    Ok(tokens)
}

struct Parser<'a> {
    tokens: Vec<&'a str>,
    at: usize,
    nodes: Vec<Node>,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<&'a str> {
        self.tokens.get(self.at).copied()
    }
    fn take(&mut self) -> Result<&'a str, &'static str> {
        let token = self
            .peek()
            .ok_or("incomplete filter: expected a predicate or value")?;
        self.at += 1;
        Ok(token)
    }
    fn push(&mut self, node: Node) -> Result<usize, &'static str> {
        if self.nodes.len() >= MAX_NODES {
            return Err("filter accepts at most 64 expression nodes");
        }
        let index = self.nodes.len();
        self.nodes.push(node);
        Ok(index)
    }

    // libpcap gives AND and OR equal precedence, evaluated left to right.
    fn expression(
        &mut self,
        inherited: Option<Qualifier>,
        depth: usize,
    ) -> Result<(usize, Option<Qualifier>), &'static str> {
        let (mut left, mut qualifier) = self.unary(inherited, depth)?;
        while let Some(operator @ ("and" | "&&" | "or" | "||")) = self.peek() {
            self.at += 1;
            let (right, next) = self.unary(qualifier, depth)?;
            left = self.push(if matches!(operator, "and" | "&&") {
                Node::And(left, right)
            } else {
                Node::Or(left, right)
            })?;
            qualifier = next;
        }
        Ok((left, qualifier))
    }

    fn unary(
        &mut self,
        inherited: Option<Qualifier>,
        depth: usize,
    ) -> Result<(usize, Option<Qualifier>), &'static str> {
        if depth > MAX_DEPTH {
            return Err("filter nesting must not exceed 16 levels");
        }
        match self.peek() {
            Some("not" | "!") => {
                self.at += 1;
                let (child, qualifier) = self.unary(inherited, depth + 1)?;
                Ok((self.push(Node::Not(child))?, qualifier))
            }
            Some("(") => {
                self.at += 1;
                let result = self.expression(inherited, depth + 1)?;
                if self.take()? != ")" {
                    return Err("missing closing parenthesis");
                }
                Ok(result)
            }
            _ => self.predicate(inherited, depth),
        }
    }

    fn predicate(
        &mut self,
        inherited: Option<Qualifier>,
        depth: usize,
    ) -> Result<(usize, Option<Qualifier>), &'static str> {
        let mut q = Qualifier {
            direction: Direction::Either,
            kind: Kind::Host,
            protocol: None,
            ipv6: None,
        };
        let mut explicit = false;
        if let Some(token) = self.peek() {
            if matches!(token, "ip" | "ip6") {
                self.at += 1;
                q.ipv6 = Some(token == "ip6");
                explicit = true;
            } else if named_protocol(token) {
                self.at += 1;
                q.protocol = Some(protocol(token)?);
                explicit = true;
            }
        }
        if explicit
            && !matches!(
                self.peek(),
                Some("src" | "dst" | "host" | "net" | "port" | "portrange")
            )
        {
            let node = if let Some(p) = q.protocol {
                Node::Protocol(p)
            } else {
                Node::Family(q.ipv6.unwrap())
            };
            return Ok((self.push(node)?, None));
        }
        if let Some(direction @ ("src" | "dst")) = self.peek() {
            explicit = true;
            self.at += 1;
            q.direction = if direction == "src" {
                Direction::Source
            } else {
                Direction::Destination
            };
            if matches!(self.peek(), Some("or" | "and"))
                && self.tokens.get(self.at + 1).copied()
                    == Some(if direction == "src" { "dst" } else { "src" })
            {
                q.direction = if self.take()? == "and" {
                    Direction::Both
                } else {
                    Direction::Either
                };
                self.at += 1;
            }
        }
        match self.peek() {
            Some(token @ ("host" | "net" | "port" | "portrange")) => {
                self.at += 1;
                q.kind = match token {
                    "net" => Kind::Net,
                    "port" => Kind::Port,
                    "portrange" => Kind::PortRange,
                    _ => Kind::Host,
                };
            }
            _ if !explicit => q = inherited.ok_or(EXPECTED)?,
            // tcpdump's omitted type qualifier defaults to host.
            _ => (),
        }
        if matches!(q.kind, Kind::Port | Kind::PortRange)
            && q.protocol.is_some_and(|p| !matches!(p, 6 | 17 | 132))
        {
            return Err("port and portrange qualifiers require tcp, udp or sctp");
        }
        // A qualified parenthesized list inherits all qualifiers, including protocol.
        if self.peek() == Some("(") {
            let start = self.nodes.len();
            let result = self.unary(Some(q), depth)?;
            if self.nodes[start..].iter().any(|node| match node {
                Node::Value(qualifier, _) => *qualifier != q,
                Node::Protocol(_) | Node::Family(_) => true,
                _ => false,
            }) {
                return Err(
                    "qualified parentheses accept only values with the inherited qualifiers",
                );
            }
            return Ok(result);
        }
        let token = self.take()?;
        let value = match q.kind {
            Kind::Host => {
                if token.contains('/') {
                    return Err("host requires a numeric IP; use net for CIDR");
                }
                Value::Network(host(token).map_err(|_| {
                    "host requires a numeric IPv4 or IPv6 address; DNS is unsupported"
                })?)
            }
            Kind::Net => {
                let mask = if self.peek() == Some("mask") {
                    self.at += 1;
                    Some(self.take()?)
                } else {
                    None
                };
                Value::Network(network(token, mask)?)
            }
            Kind::Port => {
                let p = port(token)?;
                Value::Ports(p, p)
            }
            Kind::PortRange => {
                let (low, high) = token
                    .split_once('-')
                    .or_else(|| token.split_once(':'))
                    .ok_or("portrange requires numeric LOW-HIGH")?;
                let (low, high) = (port(low)?, port(high)?);
                if low > high {
                    return Err("portrange lower bound must not exceed upper bound");
                }
                Value::Ports(low, high)
            }
        };
        if let Value::Network(net) = &value {
            if q.ipv6.is_some_and(|v6| v6 != net.addr().is_ipv6()) {
                return Err("IP family qualifier conflicts with address family");
            }
        }
        Ok((self.push(Node::Value(q, value))?, Some(q)))
    }
}

fn named_protocol(token: &str) -> bool {
    matches!(
        token.to_ascii_lowercase().as_str(),
        "tcp" | "udp" | "icmp" | "icmp6" | "icmpv6" | "ipv6-icmp" | "sctp" | "gre"
    )
}

fn network(value: &str, mask: Option<&str>) -> Result<IpNet, &'static str> {
    let (address, prefix) = value
        .split_once('/')
        .map_or((value, None), |(a, p)| (a, Some(p)));
    if address.contains(':') {
        if mask.is_some() {
            return Err("net mask is supported only for IPv4; use IPv6 CIDR");
        }
        return host(value);
    }
    let mut octets = [0; 4];
    let mut count = 0;
    for octet in address.split('.') {
        if count == 4 || octet.is_empty() {
            return Err("net requires numeric IPv4/IPv6 CIDR or an abbreviated IPv4 network");
        }
        octets[count] = octet
            .parse::<u8>()
            .map_err(|_| "invalid numeric IPv4 network")?;
        count += 1;
    }
    let bits = if let Some(mask) = mask {
        if prefix.is_some() {
            return Err("use either CIDR or net mask, not both");
        }
        let mask: u32 = mask
            .parse::<Ipv4Addr>()
            .map_err(|_| "net mask must be a contiguous IPv4 mask")?
            .into();
        let bits = mask.leading_ones();
        if mask != u32::MAX.checked_shl(32 - bits).unwrap_or(0) {
            return Err("net mask must be contiguous");
        }
        bits as u8
    } else if let Some(prefix) = prefix {
        prefix.parse().map_err(|_| "invalid CIDR prefix")?
    } else {
        count as u8 * 8
    };
    IpNet::new(IpAddr::V4(Ipv4Addr::from(octets)), bits)
        .map(|net| net.trunc())
        .map_err(|_| "invalid CIDR prefix")
}
