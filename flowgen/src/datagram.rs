//! Bounded, single-syscall Linux UDP batches. Neither operation retries.
#![cfg(target_os = "linux")]

use socket2::SockAddr;
use std::{
    io, mem,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    os::fd::AsRawFd,
    ptr,
};

pub const BATCH_SIZE: usize = 32;
pub const MAX_DATAGRAM: usize = 65_507;

#[derive(Clone, Copy)]
struct Packet {
    address: SocketAddr,
    slot: usize,
    len: usize,
}

/// Reusable receive storage for at most `BATCH_SIZE` IP datagrams.
/// Boxed storage is retained across calls; syscall pointers are rebuilt from
/// fresh borrows each time. Construct in the worker thread; it is not `Send`.
pub struct RecvBatch {
    bytes: Box<[u8]>,
    addresses: Box<[libc::sockaddr_storage; BATCH_SIZE]>,
    iovecs: Box<[libc::iovec; BATCH_SIZE]>,
    messages: Box<[libc::mmsghdr; BATCH_SIZE]>,
    packets: [Option<Packet>; BATCH_SIZE],
    len: usize,
    truncated: usize,
}

impl Default for RecvBatch {
    fn default() -> Self {
        Self {
            bytes: vec![0; BATCH_SIZE * MAX_DATAGRAM].into_boxed_slice(),
            // SAFETY: These C structs contain only integers and raw pointers,
            // for which all-zero is valid. Pointers are installed per call.
            addresses: Box::new(unsafe { mem::zeroed() }),
            // SAFETY: As above.
            iovecs: Box::new(unsafe { mem::zeroed() }),
            // SAFETY: As above; ancillary-data pointers remain null.
            messages: Box::new(unsafe { mem::zeroed() }),
            packets: [None; BATCH_SIZE],
            len: 0,
            truncated: 0,
        }
    }
}

impl RecvBatch {
    /// Receive once, without blocking, from an IPv4 or IPv6 UDP socket.
    /// Returns the number of complete packets available through `packets()`.
    /// Oversized/truncated packets are consumed and dropped. Thus `Ok(0)` with
    /// `truncated() > 0` is progress, not an empty socket or end of stream.
    /// An empty socket returns `WouldBlock`; `Interrupted` is not retried.
    /// Previous packets become inaccessible even when the syscall fails.
    pub fn recv(&mut self, socket: &impl AsRawFd) -> io::Result<usize> {
        self.len = 0;
        self.truncated = 0;
        // Rebuild all pointers from fresh, disjoint borrows. No stored pointer
        // is dereferenced across calls or moves of the owning boxes.
        for (((message, iovec), address), bytes) in self
            .messages
            .iter_mut()
            .zip(self.iovecs.iter_mut())
            .zip(self.addresses.iter_mut())
            .zip(self.bytes.as_chunks_mut::<MAX_DATAGRAM>().0.iter_mut())
        {
            iovec.iov_base = bytes.as_mut_ptr().cast();
            iovec.iov_len = bytes.len();
            message.msg_hdr.msg_iov = iovec;
            message.msg_hdr.msg_iovlen = 1;
            message.msg_hdr.msg_name = ptr::from_mut(address).cast();
            // namelen is an input/output field; msg_len is output-only.
            message.msg_hdr.msg_namelen = mem::size_of::<libc::sockaddr_storage>() as _;
            message.msg_hdr.msg_flags = 0;
        }

        // SAFETY: Buffers are initialized, disjoint, and exclusively borrowed.
        // Storage and descriptor arrays stay in place and alive for the call.
        // DONTWAIT applies even if the supplied socket is in blocking mode;
        // MSG_TRUNC requests the actual datagram length for oversize detection.
        let received = unsafe {
            libc::recvmmsg(
                socket.as_raw_fd(),
                self.messages.as_mut_ptr(),
                BATCH_SIZE as _,
                (libc::MSG_DONTWAIT | libc::MSG_TRUNC) as _,
                ptr::null_mut(),
            )
        };
        if received < 0 {
            return Err(io::Error::last_os_error());
        }
        for (slot, message) in self.messages[..received as usize].iter().enumerate() {
            let len = message.msg_len as usize;
            if message.msg_hdr.msg_flags & libc::MSG_TRUNC != 0 || len > MAX_DATAGRAM {
                self.truncated += 1;
                continue;
            }
            let address = match socket_address(&self.addresses[slot], message.msg_hdr.msg_namelen) {
                Ok(address) => address,
                Err(error) => {
                    self.len = 0;
                    return Err(error);
                }
            };
            self.packets[self.len] = Some(Packet { address, slot, len });
            self.len += 1;
        }
        Ok(self.len)
    }

    /// Complete packets in receive order, borrowing the reusable payloads.
    /// Zero-length datagrams are represented by an empty byte slice.
    pub fn packets(&self) -> impl ExactSizeIterator<Item = (SocketAddr, &[u8])> + '_ {
        self.packets[..self.len].iter().map(|packet| {
            let packet = packet.unwrap();
            let start = packet.slot * MAX_DATAGRAM;
            (packet.address, &self.bytes[start..start + packet.len])
        })
    }

    /// Number of truncated/oversized datagrams dropped by the last receive.
    pub fn truncated(&self) -> usize {
        self.truncated
    }
}

fn socket_address(
    storage: &libc::sockaddr_storage,
    len: libc::socklen_t,
) -> io::Result<SocketAddr> {
    let family = storage.ss_family as i32;
    let expected = match family {
        libc::AF_INET => mem::size_of::<libc::sockaddr_in>(),
        libc::AF_INET6 => mem::size_of::<libc::sockaddr_in6>(),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "datagram source is not an IP address",
            ))
        }
    };
    if len as usize != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid datagram source address length",
        ));
    }
    if family == libc::AF_INET {
        // SAFETY: Family and length match sockaddr_in. Storage is initialized
        // and large enough; unaligned reads do not impose extra alignment.
        let address =
            unsafe { ptr::read_unaligned(ptr::from_ref(storage).cast::<libc::sockaddr_in>()) };
        Ok(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes()),
            u16::from_be(address.sin_port),
        )))
    } else {
        // SAFETY: The same checks above establish a complete sockaddr_in6.
        let address =
            unsafe { ptr::read_unaligned(ptr::from_ref(storage).cast::<libc::sockaddr_in6>()) };
        Ok(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::from(address.sin6_addr.s6_addr),
            u16::from_be(address.sin6_port),
            address.sin6_flowinfo,
            address.sin6_scope_id,
        )))
    }
}

/// Reusable send descriptors. Construct locally in the worker thread.
pub struct SendBatch {
    addresses: Box<[SockAddr; BATCH_SIZE]>,
    iovecs: Box<[libc::iovec; BATCH_SIZE]>,
    messages: Box<[libc::mmsghdr; BATCH_SIZE]>,
}

impl Default for SendBatch {
    fn default() -> Self {
        Self {
            addresses: Box::new(std::array::from_fn(|_| {
                SockAddr::from(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
            })),
            // SAFETY: All-zero integers/pointers are valid in these C structs.
            iovecs: Box::new(unsafe { mem::zeroed() }),
            // SAFETY: As above; null ancillary-data pointers mean no control data.
            messages: Box::new(unsafe { mem::zeroed() }),
        }
    }
}

impl SendBatch {
    /// Send once, without blocking, to the supplied IP destinations.
    ///
    /// `Ok(n)` means exactly `packets[..n]` were sent, including empty datagrams.
    /// The caller owns the unsent suffix. Linux suppresses an error encountered
    /// after a successful prefix; that error cannot be reported alongside `n`.
    /// `Err` means no packets were sent by this call. Kernel errors (including
    /// `WouldBlock`, `Interrupted`, and `EMSGSIZE`) are returned without retries.
    /// Payload lengths are left to the kernel so an oversized later packet does
    /// not prevent an earlier valid prefix from being sent.
    ///
    /// An empty batch returns `Ok(0)` without a syscall. More than `BATCH_SIZE`
    /// packets returns `InvalidInput` without sending any packet. No allocation
    /// or payload copy occurs in this function.
    pub fn send(
        &mut self,
        socket: &impl AsRawFd,
        packets: &[(SocketAddr, &[u8])],
    ) -> io::Result<usize> {
        if packets.len() > BATCH_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "datagram batch exceeds BATCH_SIZE",
            ));
        }
        if packets.is_empty() {
            return Ok(0);
        }
        // Resolve the descriptor before installing any borrowed payload pointers.
        let fd = socket.as_raw_fd();
        for (((message, iovec), address), (destination, bytes)) in self
            .messages
            .iter_mut()
            .zip(self.iovecs.iter_mut())
            .zip(self.addresses.iter_mut())
            .zip(packets)
        {
            *address = SockAddr::from(*destination);
            let header = &mut message.msg_hdr;
            // sendmmsg reads payload/address pointers despite the C API's mut types.
            iovec.iov_base = bytes.as_ptr().cast_mut().cast();
            iovec.iov_len = bytes.len();
            header.msg_iov = iovec;
            header.msg_iovlen = 1;
            header.msg_name = address.as_ptr().cast_mut().cast();
            header.msg_namelen = address.len();
        }
        // SAFETY: Addresses, descriptor arrays and borrowed payloads remain alive
        // and in place until the syscall returns. The kernel only writes message
        // lengths in the mutable descriptor array, never the borrowed payloads.
        let sent = unsafe {
            libc::sendmmsg(
                fd,
                self.messages.as_mut_ptr(),
                packets.len() as _,
                (libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL) as _,
            )
        };
        let result = if sent < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(sent as usize)
        };
        // Clear the entire attempted prefix, including unsent entries on errors.
        // No caller-owned payload pointer remains after this method returns.
        for iovec in &mut self.iovecs[..packets.len()] {
            iovec.iov_base = ptr::null_mut();
            iovec.iov_len = 0;
        }
        result
    }
}

#[cfg(test)]
pub fn send_batch(socket: &impl AsRawFd, packets: &[(SocketAddr, &[u8])]) -> io::Result<usize> {
    SendBatch::default().send(socket, packets)
}

#[cfg(test)]
mod tests {
    use super::*;
    use socket2::{Domain, Protocol, Socket, Type};

    fn socket(ipv6: bool) -> Socket {
        let socket = Socket::new(
            if ipv6 { Domain::IPV6 } else { Domain::IPV4 },
            Type::DGRAM,
            Some(Protocol::UDP),
        )
        .unwrap();
        if ipv6 {
            socket.set_only_v6(true).unwrap();
        }
        // Leave the socket blocking: the wrappers must enforce nonblocking I/O.
        socket.set_recv_buffer_size(1 << 20).unwrap();
        let address: SocketAddr = if ipv6 { "[::1]:0" } else { "127.0.0.1:0" }
            .parse()
            .unwrap();
        socket.bind(&address.into()).unwrap();
        socket
    }

    fn address(socket: &Socket) -> SocketAddr {
        socket.local_addr().unwrap().as_socket().unwrap()
    }

    fn assert_empty(batch: &mut RecvBatch, receiver: &Socket) {
        let error = batch.recv(receiver).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(error.raw_os_error(), Some(libc::EAGAIN));
        assert_eq!(batch.packets().len(), 0);
        assert_eq!(batch.truncated(), 0);
    }

    fn round_trip(ipv6: bool) {
        let sender = socket(ipv6);
        let receiver = socket(ipv6);
        let destination = address(&receiver);
        let source = address(&sender);
        let mut batch = RecvBatch::default();
        assert_empty(&mut batch, &receiver);
        let maximum = vec![0xa5; MAX_DATAGRAM];
        let packets: &[(SocketAddr, &[u8])] = &[
            (destination, b"first"),
            (destination, b""),
            (destination, &maximum),
            (destination, b"last"),
        ];
        assert_eq!(send_batch(&sender, packets).unwrap(), packets.len());
        assert_eq!(batch.recv(&receiver).unwrap(), packets.len());
        assert_eq!(batch.truncated(), 0);
        for ((actual_source, actual), (_, expected)) in batch.packets().zip(packets) {
            assert_eq!(actual_source, source);
            assert_eq!(actual, *expected);
        }
        assert_empty(&mut batch, &receiver);
    }

    #[test]
    fn ipv4_actual_lengths_source_and_zero_length() {
        round_trip(false);
    }

    #[test]
    fn ipv6_actual_lengths_source_and_zero_length() {
        round_trip(true);
    }

    #[test]
    fn std_udp_socket_uses_the_same_borrowed_batch_api() {
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let destination = receiver.local_addr().unwrap();
        let mut batch = RecvBatch::default();
        assert_eq!(
            batch.recv(&receiver).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(send_batch(&sender, &[(destination, b"std")]).unwrap(), 1);
        assert_eq!(batch.recv(&receiver).unwrap(), 1);
        assert_eq!(
            batch.packets().next(),
            Some((sender.local_addr().unwrap(), b"std".as_slice()))
        );
    }

    #[test]
    fn receive_drops_truncated_packets_without_hiding_following_packets() {
        // IPv6 supports UDP payloads larger than the IPv4 maximum used by
        // flowgen, so this exercises a real kernel MSG_TRUNC indication.
        let sender = socket(true);
        let receiver = socket(true);
        let destination = address(&receiver);
        let oversized = vec![0x5a; MAX_DATAGRAM + 1];
        let mut batch = RecvBatch::default();
        let packets: &[(SocketAddr, &[u8])] = &[
            (destination, b"before"),
            (destination, &oversized),
            (destination, b""),
            (destination, b"after"),
        ];
        assert_eq!(send_batch(&sender, packets).unwrap(), 4);
        assert_eq!(batch.recv(&receiver).unwrap(), 3);
        assert_eq!(batch.truncated(), 1);
        let actual: Vec<_> = batch.packets().map(|(_, bytes)| bytes).collect();
        assert_eq!(actual, [b"before".as_slice(), b"", b"after"]);

        assert_eq!(
            send_batch(&sender, &[(destination, &oversized)]).unwrap(),
            1
        );
        assert_eq!(batch.recv(&receiver).unwrap(), 0);
        assert_eq!(batch.packets().len(), 0);
        assert_eq!(batch.truncated(), 1);
        assert_empty(&mut batch, &receiver);
    }

    #[test]
    fn send_prefix_stops_at_kernel_error_and_never_sends_suffix() {
        let sender = socket(false);
        let receiver = socket(false);
        let destination = address(&receiver);
        let oversized = vec![0; MAX_DATAGRAM + 1];
        let packets: &[(SocketAddr, &[u8])] = &[
            (destination, b"prefix"),
            (destination, &oversized),
            (destination, b"suffix"),
        ];
        let mut sends = SendBatch::default();
        assert_eq!(sends.send(&sender, packets).unwrap(), 1);
        assert_payloads_cleared(&sends);
        let mut batch = RecvBatch::default();
        assert_eq!(batch.recv(&receiver).unwrap(), 1);
        assert_eq!(batch.packets().next().unwrap().1, b"prefix");
        assert_empty(&mut batch, &receiver);
        assert_eq!(
            sends
                .send(&sender, &packets[1..])
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EMSGSIZE)
        );
        assert_payloads_cleared(&sends);
        assert_empty(&mut batch, &receiver);
        assert_eq!(sends.send(&sender, &packets[2..]).unwrap(), 1);
        assert_payloads_cleared(&sends);
        assert_eq!(batch.recv(&receiver).unwrap(), 1);
        assert_eq!(batch.packets().next().unwrap().1, b"suffix");
        assert_empty(&mut batch, &receiver);
    }

    #[test]
    fn sends_to_multiple_destinations_and_receives_multiple_sources() {
        let sender = socket(false);
        let first = socket(false);
        let second = socket(false);
        let packets: &[(SocketAddr, &[u8])] = &[
            (address(&first), b"one"),
            (address(&second), b"two"),
            (address(&first), b"three"),
        ];
        assert_eq!(send_batch(&sender, packets).unwrap(), 3);
        let mut batch = RecvBatch::default();
        assert_eq!(batch.recv(&first).unwrap(), 2);
        assert_eq!(
            batch.packets().collect::<Vec<_>>(),
            [
                (address(&sender), b"one".as_slice()),
                (address(&sender), b"three")
            ]
        );
        assert_eq!(batch.recv(&second).unwrap(), 1);
        assert_eq!(
            batch.packets().next(),
            Some((address(&sender), b"two".as_slice()))
        );

        assert_eq!(send_batch(&first, &[(address(&sender), b"a")]).unwrap(), 1);
        assert_eq!(send_batch(&second, &[(address(&sender), b"b")]).unwrap(), 1);
        assert_eq!(batch.recv(&sender).unwrap(), 2);
        assert_eq!(
            batch.packets().collect::<Vec<_>>(),
            [(address(&first), b"a".as_slice()), (address(&second), b"b")]
        );
    }

    #[test]
    fn batches_reuse_stable_storage_across_moves_and_short_full_ipv4_ipv6_calls() {
        let endpoints = [(socket(false), socket(false)), (socket(true), socket(true))];
        let mut batch = RecvBatch::default();
        let mut sends = SendBatch::default();
        let pointer = batch.bytes.as_ptr();
        let recv_pointers = (
            batch.addresses.as_ptr(),
            batch.iovecs.as_ptr(),
            batch.messages.as_ptr(),
        );
        let send_pointers = (
            sends.addresses.as_ptr(),
            sends.iovecs.as_ptr(),
            sends.messages.as_ptr(),
        );
        for cycle in 0..64 {
            let (sender, receiver) = &endpoints[cycle % 2];
            let (other_sender, other_receiver) = &endpoints[(cycle + 1) % 2];
            let payloads: [Vec<u8>; BATCH_SIZE] =
                std::array::from_fn(|index| vec![(index + cycle) as u8; (index * 7 + cycle) % 256]);
            let packets: [_; BATCH_SIZE] =
                std::array::from_fn(|index| (address(receiver), payloads[index].as_slice()));
            assert_eq!(sends.send(sender, &packets).unwrap(), BATCH_SIZE);
            assert_payloads_cleared(&sends);
            assert_eq!(batch.recv(receiver).unwrap(), BATCH_SIZE);
            assert_eq!(batch.packets().len(), BATCH_SIZE);
            for ((source, bytes), expected) in batch.packets().zip(&payloads) {
                assert_eq!(source, address(sender));
                assert_eq!(bytes, expected);
            }
            // Move both owners and switch address family for a short batch.
            // Old suffix descriptors and borrowed payloads must not be used.
            let mut moved = Box::new(batch);
            let mut moved_sends = Box::new(sends);
            assert_eq!(
                moved_sends
                    .send(other_sender, &[(address(other_receiver), b"")])
                    .unwrap(),
                1
            );
            assert_payloads_cleared(&moved_sends);
            assert_eq!(moved.recv(other_receiver).unwrap(), 1);
            assert_eq!(
                moved.packets().next(),
                Some((address(other_sender), b"".as_slice()))
            );
            batch = *moved;
            sends = *moved_sends;
            assert_eq!(batch.bytes.as_ptr(), pointer);
            assert_eq!(batch.bytes.len(), BATCH_SIZE * MAX_DATAGRAM);
            assert_eq!(
                (
                    batch.addresses.as_ptr(),
                    batch.iovecs.as_ptr(),
                    batch.messages.as_ptr()
                ),
                recv_pointers
            );
            assert_eq!(
                (
                    sends.addresses.as_ptr(),
                    sends.iovecs.as_ptr(),
                    sends.messages.as_ptr()
                ),
                send_pointers
            );
            assert_empty(&mut batch, receiver);
            assert_empty(&mut batch, other_receiver);
        }
    }

    fn assert_payloads_cleared(batch: &SendBatch) {
        for iovec in batch.iovecs.iter() {
            assert!(iovec.iov_base.is_null());
            assert_eq!(iovec.iov_len, 0);
        }
    }

    #[test]
    fn empty_and_overfull_send_batches_have_no_side_effects() {
        let sender = socket(false);
        let receiver = socket(false);
        assert_eq!(send_batch(&sender, &[]).unwrap(), 0);
        let packets = [(address(&receiver), b"x".as_slice()); BATCH_SIZE + 1];
        assert_eq!(
            send_batch(&sender, &packets).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_empty(&mut RecvBatch::default(), &receiver);
    }

    #[test]
    fn malformed_sockaddr_lengths_are_rejected() {
        for family in [libc::AF_INET, libc::AF_INET6] {
            // SAFETY: All-zero bytes are valid for the integer-only storage.
            let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
            storage.ss_family = family as _;
            assert_eq!(
                socket_address(&storage, 0).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
        // SAFETY: As above.
        let storage = unsafe { mem::zeroed() };
        assert_eq!(
            socket_address(&storage, 0).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
