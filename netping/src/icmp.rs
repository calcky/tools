use crate::{net, options::Options};
use pnet_packet::{
    icmp::{echo_reply::EchoReplyPacket, IcmpPacket, IcmpTypes},
    icmpv6::{echo_reply::EchoReplyPacket as EchoReplyV6, Icmpv6Types},
    ipv4::Ipv4Packet,
};
use socket2::{Domain, Protocol, Socket, Type};
use std::{io, net::SocketAddr};

pub struct Icmp {
    raw: bool,
    id: u16,
    v6: bool,
}
impl Icmp {
    pub fn socket(o: &Options, addr: SocketAddr, session: u64) -> io::Result<(Socket, Self)> {
        let domain = if o.v6 { Domain::IPV6 } else { Domain::IPV4 };
        let protocol = if o.v6 {
            Protocol::ICMPV6
        } else {
            Protocol::ICMPV4
        };
        let (socket, raw) = match Socket::new(domain, Type::DGRAM, Some(protocol)) {
            Ok(s) => (s, false),
            Err(_) => (Socket::new(domain, Type::RAW, Some(protocol)).map_err(|e| {
                io::Error::new(e.kind(), format!("ICMP socket: {e}; allow ping sockets via net.ipv4.ping_group_range, or use CAP_NET_RAW/root"))
            })?, true),
        };
        socket.set_nonblocking(true)?;
        if raw {
            net::only_echo_replies(&socket, o.v6)?;
        }
        socket.connect(&SocketAddr::new(addr.ip(), 0).into())?;
        let id = if raw {
            session as u16
        } else {
            socket
                .local_addr()?
                .as_socket()
                .ok_or_else(|| io::Error::other("missing ICMP socket address"))?
                .port()
        };
        Ok((socket, Self { raw, id, v6: o.v6 }))
    }
    pub fn request(&self, payload: &[u8], seq: u64) -> Vec<u8> {
        let mut data = vec![0; 8 + payload.len()];
        data[0] = if self.v6 { 128 } else { 8 };
        data[4..6].copy_from_slice(&self.id.to_be_bytes());
        data[6..8].copy_from_slice(&(seq as u16).to_be_bytes());
        data[8..].copy_from_slice(payload);
        if !self.v6 {
            let sum = pnet_packet::icmp::checksum(&IcmpPacket::new(&data).unwrap());
            data[2..4].copy_from_slice(&sum.to_be_bytes());
        }
        data
    }
    pub fn payload<'a>(&self, data: &'a [u8]) -> Option<&'a [u8]> {
        let data = if self.raw && !self.v6 {
            let ip = Ipv4Packet::new(data)?;
            let offset = ip.get_header_length() as usize * 4;
            if offset < 20 {
                return None;
            }
            data.get(offset..)?
        } else {
            data
        };
        if self.v6 {
            let p = EchoReplyV6::new(data)?;
            if p.get_icmpv6_type() != Icmpv6Types::EchoReply
                || p.get_icmpv6_code().0 != 0
                || p.get_identifier() != self.id
            {
                return None;
            }
        } else {
            let p = EchoReplyPacket::new(data)?;
            if p.get_icmp_type() != IcmpTypes::EchoReply
                || p.get_icmp_code().0 != 0
                || p.get_identifier() != self.id
                || pnet_packet::icmp::checksum(&IcmpPacket::new(data)?) != p.get_checksum()
            {
                return None;
            }
        }
        data.get(8..)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn request_checksum_and_reply_validation() {
        let i = Icmp {
            raw: false,
            id: 123,
            v6: false,
        };
        let payload = crate::wire::encode(4, 7, 64);
        let mut b = i.request(&payload, 7);
        assert_eq!(
            pnet_packet::icmp::checksum(&IcmpPacket::new(&b).unwrap()),
            IcmpPacket::new(&b).unwrap().get_checksum()
        );
        assert!(i.payload(&b).is_none());
        b[0] = 0;
        b[2] = 0;
        b[3] = 0;
        let c = pnet_packet::icmp::checksum(&IcmpPacket::new(&b).unwrap());
        b[2..4].copy_from_slice(&c.to_be_bytes());
        assert_eq!(i.payload(&b), Some(payload.as_slice()));
        b[4] ^= 1;
        assert!(i.payload(&b).is_none());
    }
}
