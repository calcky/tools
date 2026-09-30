use anyhow::{bail, Context, Result};
use std::{
    collections::{HashMap, HashSet},
    ffi::CStr,
    fs,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Errors {
    pub rx_dropped: u64,
    pub rx_invalid: u64,
    pub rx_full: u64,
    pub fill_empty: u64,
    pub tx_invalid: u64,
    pub tx_empty: u64,
}

impl Errors {
    pub fn rx_total(self) -> u64 {
        self.rx_dropped
            .saturating_add(self.rx_invalid)
            .saturating_add(self.rx_full)
    }

    pub fn tx_total(self) -> u64 {
        self.tx_invalid
    }

    pub fn total(self) -> u64 {
        self.rx_total().saturating_add(self.tx_total())
    }

    pub fn delta(self, old: Self) -> Self {
        Self {
            rx_dropped: self.rx_dropped.saturating_sub(old.rx_dropped),
            rx_invalid: self.rx_invalid.saturating_sub(old.rx_invalid),
            rx_full: self.rx_full.saturating_sub(old.rx_full),
            fill_empty: self.fill_empty.saturating_sub(old.fill_empty),
            tx_invalid: self.tx_invalid.saturating_sub(old.tx_invalid),
            tx_empty: self.tx_empty.saturating_sub(old.tx_empty),
        }
    }
}

#[derive(Clone, Default, Debug)]
pub struct Socket {
    pub inode: u32,
    pub ifindex: u32,
    pub queue: u32,
    pub iface: String,
    pub owner: String,
    pub zero_copy: bool,
    pub umem_bytes: u64,
    pub chunk_bytes: u32,
    pub rings: [u32; 4], // RX, TX, fill, completion capacities; not occupancy.
    pub errors: Errors,
}

fn u32_at(bytes: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_ne_bytes(
        bytes.get(at..at + 4).context("truncated u32")?.try_into()?,
    ))
}

fn u64_at(bytes: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_ne_bytes(
        bytes.get(at..at + 8).context("truncated u64")?.try_into()?,
    ))
}

fn align(size: usize) -> usize {
    (size + 3) & !3
}

fn parse_socket(bytes: &[u8]) -> Result<Socket> {
    if bytes.len() < 16 || bytes[0] != 44 {
        bail!("invalid XDP diagnostic message");
    }
    let mut socket = Socket {
        inode: u32_at(bytes, 4)?,
        ..Default::default()
    };
    let mut at = 16;
    while at + 4 <= bytes.len() {
        let size = u16::from_ne_bytes(bytes[at..at + 2].try_into()?) as usize;
        let kind = u16::from_ne_bytes(bytes[at + 2..at + 4].try_into()?) & 0x3fff;
        if size < 4 || at + size > bytes.len() {
            bail!("malformed XDP diagnostic attribute");
        }
        let value = &bytes[at + 4..at + size];
        match kind {
            1 if value.len() >= 8 => {
                socket.ifindex = u32_at(value, 0)?;
                socket.queue = u32_at(value, 4)?;
            }
            3 | 4 | 6 | 7 if value.len() >= 4 => {
                let slot = match kind {
                    3 => 0,
                    4 => 1,
                    6 => 2,
                    _ => 3,
                };
                socket.rings[slot] = u32_at(value, 0)?;
            }
            5 if value.len() >= 40 => {
                socket.umem_bytes = u64_at(value, 0)?;
                socket.chunk_bytes = u32_at(value, 16)?;
                socket.zero_copy = u32_at(value, 32)? & 1 != 0;
            }
            9 if value.len() >= 48 => {
                socket.errors = Errors {
                    rx_dropped: u64_at(value, 0)?,
                    rx_invalid: u64_at(value, 8)?,
                    rx_full: u64_at(value, 16)?,
                    fill_empty: u64_at(value, 24)?,
                    tx_invalid: u64_at(value, 32)?,
                    tx_empty: u64_at(value, 40)?,
                };
            }
            _ => {}
        }
        at += align(size);
    }
    Ok(socket)
}

pub fn iface_name(index: u32) -> String {
    let mut name = [0 as libc::c_char; libc::IF_NAMESIZE];
    let ptr = unsafe { libc::if_indextoname(index, name.as_mut_ptr()) };
    if ptr.is_null() {
        format!("if{index}")
    } else {
        unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned()
    }
}

pub fn snapshot() -> Result<Vec<Socket>> {
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_SOCK_DIAG,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("open NETLINK_SOCK_DIAG");
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let timeout = libc::timeval {
        tv_sec: 2,
        tv_usec: 0,
    };
    let result = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&timeout as *const libc::timeval).cast(),
            std::mem::size_of_val(&timeout) as u32,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error()).context("set diagnostic receive timeout");
    }
    let mut req = [0_u8; 36];
    req[..4].copy_from_slice(&36_u32.to_ne_bytes());
    req[4..6].copy_from_slice(&20_u16.to_ne_bytes()); // SOCK_DIAG_BY_FAMILY
    req[6..8].copy_from_slice(&(0x301_u16).to_ne_bytes()); // REQUEST | DUMP
    req[8..12].copy_from_slice(&1_u32.to_ne_bytes());
    req[16] = 44; // AF_XDP
    req[24..28].copy_from_slice(&31_u32.to_ne_bytes()); // INFO, rings, UMEM, meminfo, stats
    let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    kernel.nl_family = libc::AF_NETLINK as u16;
    let sent = unsafe {
        libc::sendto(
            fd.as_raw_fd(),
            req.as_ptr().cast(),
            req.len(),
            0,
            (&kernel as *const libc::sockaddr_nl).cast(),
            std::mem::size_of_val(&kernel) as u32,
        )
    };
    if sent < 0 {
        return Err(std::io::Error::last_os_error()).context("send XDP socket dump");
    }
    let mut sockets = Vec::new();
    let mut buf = vec![0_u8; 1 << 20];
    loop {
        let size = unsafe {
            libc::recv(
                fd.as_raw_fd(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                libc::MSG_TRUNC,
            )
        };
        if size < 0 {
            return Err(std::io::Error::last_os_error()).context("receive XDP socket dump");
        }
        if size == 0 {
            bail!("XDP socket dump ended before NLMSG_DONE");
        }
        if size as usize > buf.len() {
            bail!("XDP socket diagnostic datagram was truncated");
        }
        let mut at = 0;
        let size = size as usize;
        while at + 16 <= size {
            let len = u32_at(&buf, at)? as usize;
            if len < 16 || at + len > size {
                bail!("malformed netlink message");
            }
            let kind = u16::from_ne_bytes(buf[at + 4..at + 6].try_into()?);
            let flags = u16::from_ne_bytes(buf[at + 6..at + 8].try_into()?);
            if flags & 0x10 != 0 {
                bail!("XDP socket dump interrupted; retry the snapshot");
            }
            if u32_at(&buf, at + 8)? != 1 {
                bail!("unexpected XDP dump sequence");
            }
            let payload = &buf[at + 16..at + len];
            match kind {
                3 => {
                    if payload.len() >= 4 {
                        let errno = u32_at(payload, 0)? as i32;
                        if errno != 0 {
                            return Err(std::io::Error::from_raw_os_error(-errno))
                                .context("finish XDP socket dump");
                        }
                    }
                    return Ok(sockets);
                }
                2 => {
                    // NLMSG_ERROR
                    let errno = u32_at(payload, 0)? as i32;
                    if errno != 0 {
                        return Err(std::io::Error::from_raw_os_error(-errno))
                            .context("XDP socket dump");
                    }
                }
                20 => sockets.push(parse_socket(payload)?),
                _ => {}
            }
            at += align(len);
        }
    }
}

// /proc ownership is advisory: processes can share an FD, and permissions can hide owners.
pub fn owners(inodes: &HashSet<u32>) -> HashMap<u32, String> {
    let mut result = HashMap::new();
    let mut remaining = inodes.clone();
    if remaining.is_empty() {
        return result;
    }
    let Ok(processes) = fs::read_dir("/proc") else {
        return result;
    };
    for process in processes.flatten() {
        let Ok(pid) = process.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let comm = fs::read_to_string(process.path().join("comm"))
            .unwrap_or_else(|_| "?".into())
            .trim()
            .chars()
            .map(|ch| if ch.is_control() { '?' } else { ch })
            .collect::<String>();
        let Ok(fds) = fs::read_dir(process.path().join("fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            let Ok(target) = fs::read_link(fd.path()) else {
                continue;
            };
            let target = target.to_string_lossy();
            let Some(inode) = target
                .strip_prefix("socket:[")
                .and_then(|s| s.strip_suffix(']'))
            else {
                continue;
            };
            let Ok(inode) = inode.parse::<u32>() else {
                continue;
            };
            if !remaining.remove(&inode) {
                continue;
            }
            result
                .entry(inode)
                .or_insert_with(|| format!("{comm}({pid})"));
            if remaining.is_empty() {
                return result;
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_xsk_diagnostic_fields() {
        let mut msg = vec![0_u8; 16];
        msg[0] = 44;
        msg[4..8].copy_from_slice(&77_u32.to_ne_bytes());
        for (kind, data) in [
            (1_u16, [5_u32.to_ne_bytes(), 3_u32.to_ne_bytes()].concat()),
            (3, 1024_u32.to_ne_bytes().to_vec()),
            (
                9,
                [
                    11_u64.to_ne_bytes(),
                    2_u64.to_ne_bytes(),
                    0_u64.to_ne_bytes(),
                    5_u64.to_ne_bytes(),
                    0_u64.to_ne_bytes(),
                    0_u64.to_ne_bytes(),
                ]
                .concat(),
            ),
        ] {
            let size = (data.len() + 4) as u16;
            msg.extend_from_slice(&size.to_ne_bytes());
            msg.extend_from_slice(&kind.to_ne_bytes());
            msg.extend_from_slice(&data);
            msg.resize(align(msg.len()), 0);
        }
        let socket = parse_socket(&msg).unwrap();
        assert_eq!((socket.inode, socket.ifindex, socket.queue), (77, 5, 3));
        assert_eq!(socket.rings[0], 1024);
        assert_eq!(socket.errors.total(), 13);
    }

    #[test]
    fn rejects_truncated_attribute() {
        let mut msg = vec![0_u8; 16];
        msg[0] = 44;
        msg.extend_from_slice(&10_u16.to_ne_bytes());
        msg.extend_from_slice(&1_u16.to_ne_bytes());
        assert!(parse_socket(&msg).is_err());
    }

    #[test]
    fn umem_offsets_match_the_kernel_uapi() {
        let mut msg = vec![0_u8; 16];
        msg[0] = 44;
        let mut umem = [0_u8; 40];
        umem[..8].copy_from_slice(&1_048_576_u64.to_ne_bytes());
        umem[16..20].copy_from_slice(&4096_u32.to_ne_bytes());
        umem[20..24].copy_from_slice(&256_u32.to_ne_bytes());
        umem[32..36].copy_from_slice(&1_u32.to_ne_bytes());
        msg.extend_from_slice(&44_u16.to_ne_bytes());
        msg.extend_from_slice(&5_u16.to_ne_bytes());
        msg.extend_from_slice(&umem);
        let socket = parse_socket(&msg).unwrap();
        assert_eq!(socket.umem_bytes, 1_048_576);
        assert_eq!(socket.chunk_bytes, 4096);
        assert!(socket.zero_copy);
    }

    #[test]
    fn empty_ring_events_are_not_errors() {
        let events = Errors {
            fill_empty: 300,
            tx_empty: 400,
            ..Default::default()
        };
        assert_eq!(events.total(), 0);
    }

    #[test]
    fn ownership_scan_is_empty_without_target_sockets() {
        assert!(owners(&HashSet::new()).is_empty());
    }
}
