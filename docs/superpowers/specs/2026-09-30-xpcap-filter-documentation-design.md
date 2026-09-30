# xpcap Filter Documentation Design

## Scope

Document the packet-filter grammar that xpcap currently accepts through
`pktbaffle`, without claiming compatibility with every tcpdump/libpcap
extension and without changing the parser in this update.

## User-facing changes

- Add a complete filter reference to `xpcap/README.md`.
- Add a concise Chinese and English reference to the localized xpcap pages.
- Extend `xpcap -h` with representative address, port, protocol, link-layer,
  length, raw-field, and boolean examples.
- State the execution model: named-interface PCAP filters attach to the packet
  socket; XDP/XSK filters run in the probe; `-i any` PCAP filters run after
  receipt; XDP/XSK filters are limited to 128 classic-BPF instructions.

## Supported categories

The documentation will cover hosts and networks, ports and port ranges, IP
protocols, source/destination qualifiers, boolean operators and precedence,
Ethernet addresses and EtherTypes, VLAN/MPLS/PPPoE, broadcast and multicast,
packet length, raw byte access, TCP flag constants, and ICMP constants.

## Validation

Add or retain tests that compile representative expressions from every listed
category with the Ethernet classic-BPF target. Run formatting, tests, and
Clippy. The update must not modify unrelated worktree changes.
