use crate::event::Event;
use anyhow::{bail, Context, Result};
use pktbaffle::Program;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

pub struct PacketSocket {
    fd: OwnedFd,
    ifindex: u32,
    buffer: Vec<u8>,
    capture_in: bool,
    capture_out: bool,
    sample: u32,
    sample_next: u32,
    pub filtered: u64,
    pub sampled: u64,
    pub read_errors: u64,
}

fn take_sample(next: &mut u32, period: u32) -> bool {
    let take = *next == 0;
    *next += 1;
    if *next == period {
        *next = 0;
    }
    take
}

#[repr(C)]
#[derive(Default)]
struct PacketStats {
    received: u32,
    dropped: u32,
}

impl PacketSocket {
    pub fn open(
        ifindex: u32,
        snaplen: u32,
        capture_in: bool,
        capture_out: bool,
        expression: Option<&Program>,
        sample: u32,
    ) -> Result<Self> {
        if sample == 0 {
            bail!("sample period must be positive");
        }
        let protocol = (libc::ETH_P_ALL as u16).to_be() as i32;
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                protocol,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error())
                .context("open AF_PACKET socket (CAP_NET_RAW required)");
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let address = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as u16,
            sll_protocol: protocol as u16,
            sll_ifindex: ifindex as i32,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };
        if unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&address as *const libc::sockaddr_ll).cast(),
                std::mem::size_of_val(&address) as libc::socklen_t,
            )
        } < 0
        {
            return Err(std::io::Error::last_os_error()).context("bind AF_PACKET socket");
        }
        if let Some(program) = expression {
            let instructions = program.instructions();
            let length = u16::try_from(instructions.len()).context("capture filter too large")?;
            let filter = libc::sock_fprog {
                len: length,
                filter: instructions.as_ptr().cast_mut().cast(),
            };
            if unsafe {
                libc::setsockopt(
                    fd.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_ATTACH_FILTER,
                    (&filter as *const libc::sock_fprog).cast(),
                    std::mem::size_of_val(&filter) as libc::socklen_t,
                )
            } < 0
            {
                return Err(std::io::Error::last_os_error())
                    .context("attach capture filter to AF_PACKET socket");
            }
        }
        Ok(Self {
            fd,
            ifindex,
            buffer: vec![0; snaplen as usize],
            capture_in,
            capture_out,
            sample,
            sample_next: 0,
            filtered: 0,
            sampled: 0,
            read_errors: 0,
        })
    }

    pub fn fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }

    pub fn drops(&self) -> Result<u64> {
        let mut stats = PacketStats::default();
        let mut size = std::mem::size_of::<PacketStats>() as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                self.fd.as_raw_fd(),
                libc::SOL_PACKET,
                6, // PACKET_STATISTICS; reading also resets the kernel counters.
                (&mut stats as *mut PacketStats).cast(),
                &mut size,
            )
        };
        if result < 0 {
            return Err(std::io::Error::last_os_error()).context("read packet socket drops");
        }
        if size < std::mem::size_of::<PacketStats>() as libc::socklen_t {
            bail!("short packet socket statistics");
        }
        Ok(stats.dropped as u64)
    }

    pub fn drain(&mut self, mut record: impl FnMut(Event<'_>)) -> Result<()> {
        // Bound each pass so a busy packet socket cannot starve BPF events or -T.
        for _ in 0..256 {
            let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
            let mut address_len = std::mem::size_of_val(&address) as libc::socklen_t;
            let length = unsafe {
                libc::recvfrom(
                    self.fd.as_raw_fd(),
                    self.buffer.as_mut_ptr().cast(),
                    self.buffer.len(),
                    libc::MSG_TRUNC | libc::MSG_DONTWAIT,
                    (&mut address as *mut libc::sockaddr_ll).cast(),
                    &mut address_len,
                )
            };
            if length < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::WouldBlock {
                    return Ok(());
                }
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                self.read_errors += 1;
                return Err(error).context("read AF_PACKET socket");
            }
            if address_len < std::mem::size_of::<libc::sockaddr_ll>() as u32 {
                self.read_errors += 1;
                bail!("short AF_PACKET source address");
            }
            let outgoing = address.sll_pkttype == libc::PACKET_OUTGOING;
            if (outgoing && !self.capture_out) || (!outgoing && !self.capture_in) {
                self.filtered += 1;
                continue;
            }
            if !take_sample(&mut self.sample_next, self.sample) {
                self.sampled += 1;
                continue;
            }
            let packet = &self.buffer[..(length as usize).min(self.buffer.len())];
            let mut now: libc::timespec = unsafe { std::mem::zeroed() };
            if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) } < 0 {
                return Err(std::io::Error::last_os_error()).context("packet timestamp");
            }
            let timestamp = now.tv_sec as u64 * 1_000_000_000 + now.tv_nsec as u64;
            record(Event::packet(
                self.ifindex,
                timestamp,
                outgoing,
                length as u32,
                packet,
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn samples_first_and_every_nth_packet() {
        let mut next = 0;
        let decisions: Vec<_> = (0..7).map(|_| super::take_sample(&mut next, 3)).collect();
        assert_eq!(decisions, [true, false, false, true, false, false, true]);
    }

    #[test]
    fn tcpdump_expression_matches_ethernet_packet() {
        let program = pktbaffle::compile(
            "tcp and dst port 443",
            pktbaffle::LinkType::Ethernet,
            pktbaffle::Target::Classic,
        )
        .unwrap();
        let mut packet = [0u8; 14 + 20 + 20];
        packet[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        packet[14] = 0x45;
        packet[23] = 6;
        packet[36..38].copy_from_slice(&443u16.to_be_bytes());
        assert!(program.as_classic().unwrap().matches(&packet));
        packet[36..38].copy_from_slice(&80u16.to_be_bytes());
        assert!(!program.as_classic().unwrap().matches(&packet));
    }

    #[test]
    fn accepts_common_tcpdump_expression_forms() {
        for expression in [
            "tcp and (port 80 or port 443)",
            "host 192.0.2.1 and udp",
            "src net 192.0.2.0/24 and dst portrange 8000-9000",
        ] {
            assert!(
                pktbaffle::compile(
                    expression,
                    pktbaffle::LinkType::Ethernet,
                    pktbaffle::Target::Classic,
                )
                .is_ok(),
                "{expression}"
            );
        }
        assert!(pktbaffle::compile(
            "tcp and (",
            pktbaffle::LinkType::Ethernet,
            pktbaffle::Target::Classic,
        )
        .is_err());
    }
}
