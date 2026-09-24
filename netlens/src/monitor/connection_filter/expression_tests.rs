use super::*;

fn endpoint(ip: &str, port: Option<u16>) -> Endpoint {
    (ip.parse().unwrap(), port)
}

fn matches(query: &str, proto: u8, source: Endpoint, destination: Endpoint) -> bool {
    ConnectionFilter::parse(query).unwrap().unwrap().matches(
        proto,
        source,
        destination,
        &[source, destination, endpoint("10.0.0.1", Some(8443))],
    )
}

#[test]
fn expressions_use_only_original_tuple_and_legacy_keeps_nat() {
    let source = endpoint("192.0.2.5", Some(12345));
    let destination = endpoint("198.51.100.1", Some(443));
    for (query, expected) in [
        ("host 10.0.0.1", false),
        ("port 8443", false),
        ("host=10.0.0.1 port=8443 tcp", true),
        ("10.0.0.1 8443 tcp", true),
        ("proto=tcp tcp 443", true),
        ("tcp dst port 443", true),
        ("tcp src port 443", false),
        ("src 192.0.2.5", true),
        ("tcp dst 198.51.100.1", true),
        ("src or dst port 443", true),
        ("dst or src port 443", true),
        ("src and dst port 443", false),
        ("src and dst net 0.0.0.0/0", true),
        ("src net 192.0.2/24 and dst host 198.51.100.1", true),
        ("not (host 10.0.0.1 or port 22)", true),
        ("!(udp || port 22) && tcp", true),
    ] {
        assert_eq!(matches(query, 6, source, destination), expected, "{query}");
    }
}

#[test]
fn boolean_operators_have_pcap_precedence_and_qualifiers_are_inherited() {
    let source = endpoint("192.0.2.5", Some(12345));
    let destination = endpoint("198.51.100.1", Some(443));
    // (true OR false) AND false, not true OR (false AND false).
    assert!(!matches("tcp or udp and port 22", 6, source, destination));
    assert!(matches("tcp or (udp and port 22)", 6, source, destination));
    for query in [
        "port 22 or 443",
        "tcp port 22 or 443",
        "tcp dst port (22 or 443)",
        "dst port 22 or (80 or 443)",
    ] {
        assert!(matches(query, 6, source, destination), "{query}");
    }
    assert!(!matches("tcp port 22 or 443", 17, source, destination));
    assert!(!matches("src port 22 or 443", 6, source, destination));
    assert!(matches(
        "dst host 192.0.2.1 or 198.51.100.1",
        6,
        source,
        destination
    ));
    assert!(matches("port 443 and not 22", 6, source, destination));
    assert!(!matches("not not port 22", 6, source, destination));
}

#[test]
fn networks_support_abbreviations_masks_and_distinct_families() {
    let v4 = endpoint("192.0.2.5", None);
    let v6 = endpoint("2001:db8::1", None);
    for (query, expected) in [
        ("net 192", true),
        ("net 192.0", true),
        ("net 192.0.2", true),
        ("net 192.0.2.0", false),
        ("net 192.0.2.0/24", true),
        ("net 192.0.2 mask 255.255.255.0", true),
        ("net 0 mask 0.0.0.0", true),
        ("net 192.0.2.5 mask 255.255.255.255", true),
        ("net 2001:db8::/32", false),
        ("ip", true),
        ("ip6", false),
        ("ip net 192.0.2", true),
    ] {
        assert_eq!(matches(query, 1, v4, v4), expected, "{query}");
    }
    assert!(matches("ip6 and icmp6 and net 2001:db8::/32", 58, v6, v6));
    assert!(!matches("net 0.0.0.0/0", 58, v6, v6));
    assert!(!matches(
        "host 192.0.2.5",
        6,
        endpoint("::ffff:192.0.2.5", None),
        v6
    ));
    assert!(matches("host 192.0.2.5 or host 2001:db8::1", 6, v4, v6));
    assert!(!matches("src and dst net 0.0.0.0/0", 6, v4, v6));
    assert!(!matches("ip6", 6, v4, v6));
}

#[test]
fn ports_ranges_and_socket_local_remote_mapping() {
    let local = endpoint("192.0.2.5", Some(0));
    let remote = endpoint("198.51.100.1", Some(65535));
    for query in [
        "src port 0",
        "dst port 65535",
        "src and dst portrange 0-65535",
        "udp dst portrange 65534:65535",
    ] {
        let filter = ConnectionFilter::parse_socket(query).unwrap().unwrap();
        assert!(
            filter.matches(17, local, remote, &[local, remote]),
            "{query}"
        );
        assert!(!filter.matches(
            17,
            endpoint("192.0.2.5", None),
            endpoint("198.51.100.1", None),
            &[]
        ));
    }
    let icmp = ConnectionFilter::parse_socket("icmp or icmp6")
        .unwrap()
        .unwrap();
    assert!(!icmp.matches(6, local, remote, &[]));
    assert!(!icmp.matches(17, local, remote, &[]));
    assert!(ConnectionFilter::parse_socket("icmp").is_ok());
    assert!(ConnectionFilter::parse_socket("icmp6").is_ok());
    assert!(ConnectionFilter::parse_socket("proto=icmp").is_err());
    assert!(matches("sctp and port 65535", 132, local, remote));
}

#[test]
fn port_predicates_require_transport_protocols() {
    let source = endpoint("192.0.2.5", Some(53));
    let destination = endpoint("198.51.100.1", Some(53));
    for query in [
        "port 53",
        "portrange 52-54",
        "src and dst port 53",
        "port 22 or 53",
        "ip port 53",
    ] {
        for proto in [6, 17, 132] {
            assert!(
                matches(query, proto, source, destination),
                "{query}: {proto}"
            );
        }
        for proto in [1, 47, 58, 99] {
            assert!(
                !matches(query, proto, source, destination),
                "{query}: {proto}"
            );
        }
    }
    for (query, proto) in [
        ("tcp port 53", 6),
        ("udp portrange 52-54", 17),
        ("sctp port 53", 132),
    ] {
        assert!(matches(query, proto, source, destination));
    }
    for query in [
        "icmp port 53",
        "gre portrange 1-2",
        "icmp6 dst port 53",
        "icmp port (22 or 53)",
    ] {
        let error: &'static str = ConnectionFilter::parse(query).unwrap_err();
        assert_eq!(
            error,
            "port and portrange qualifiers require tcp, udp or sctp"
        );
    }
    // Explicit Boolean composition is valid, but cannot match a portless protocol.
    assert!(!matches("icmp and port 53", 1, source, destination));
    // Preserve legacy metadata matching, including its NAT-any endpoint semantics.
    assert!(matches("port=53 proto=99", 99, source, destination));
}

#[test]
fn invalid_and_packet_only_filters_produce_static_private_errors() {
    for query in [
        "tcp udp",
        "tcp udp and port 22",
        "tcp udp tcp udp tcp udp tcp udp tcp",
        "host=192.0.2.1 and port 22",
        "host 192.0.2.1 proto=tcp",
        "port=22 or 443",
        "host example.com",
        "host 192.0.2.0/24",
        "port ssh",
        "port 65536",
        "portrange 90-80",
        "portrange 22",
        "portrange -1:80",
        "net 192.999",
        "net 192.0.2.0/33",
        "net ::/129",
        "net 192.0/24 mask 255.255.0.0",
        "net 192 mask 255.0.255.0",
        "net 2001:db8:: mask 255.0.0.0",
        "ip6 host 192.0.2.5",
        "ip net 2001:db8::/32",
        "port 22 or",
        "and tcp",
        "()",
        "host (tcp)",
        "port (udp)",
        "tcp port (22 or udp port 53)",
        "(tcp",
        "tcp)",
        "tcp &&& udp",
        "tcp | udp",
        "!",
        "dst port",
        "tcp[13] & 2 != 0",
        "tcp and greater 100",
        "len > 42",
        "ether host 00:11:22:33:44:55",
        "vlan 10",
        "broadcast",
        "multicast",
        "inbound",
        "outbound",
        "tcp flags syn",
        "ip proto 6",
    ] {
        let error: &'static str = ConnectionFilter::parse(query).unwrap_err();
        assert!(!error.contains("192.0.2.5"), "{query}");
    }
    let parsed = ConnectionFilter::parse("host 192.0.2.5 and port 54321").unwrap();
    let debug = format!("{parsed:?}");
    assert!(!debug.contains("192.0.2.5"));
    assert!(!debug.contains("54321"));
}

#[test]
fn expressions_are_bounded_in_bytes_nodes_and_nesting() {
    assert!(ConnectionFilter::parse(&" ".repeat(513)).is_err());
    let nested = format!("{}tcp{}", "(".repeat(16), ")".repeat(16));
    assert!(ConnectionFilter::parse(&nested).is_ok());
    assert!(ConnectionFilter::parse(&format!("({nested})")).is_err());
    let long = std::iter::repeat_n("tcp", 32)
        .collect::<Vec<_>>()
        .join(" or ");
    assert!(ConnectionFilter::parse(&long).is_ok());
    assert!(ConnectionFilter::parse(&format!("{long} or tcp")).is_err());
    assert!(ConnectionFilter::parse(&format!("{}tcp", "!".repeat(17))).is_err());
    assert!(ConnectionFilter::parse("host \u{00e9}\u{00e9} || tcp").is_err());
}
