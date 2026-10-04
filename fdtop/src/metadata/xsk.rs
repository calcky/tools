use super::*;

#[derive(Default)]
pub(super) struct Cache {
    at: Option<Instant>,
    values: HashMap<u64, (u32, u32, u32)>, // cookie -> inode, ifindex, queue
    error: Option<String>,
}

impl Cache {
    pub(super) fn name(&mut self, fd: RawFd, inode: u64) -> io::Result<String> {
        // Sockets can outlive a process changing its netns. Check the socket's
        // namespace, not /proc/PID/ns/net, before using a local diagnostic dump.
        let ns = owned(unsafe { libc::ioctl(fd, 0x894c) })?; // SIOCGSKNS
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(ns.as_raw_fd(), &mut stat) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let current = fs::metadata("/proc/thread-self/ns/net")?;
        if current.ino() != stat.st_ino || current.dev() != stat.st_dev {
            return Err(io::Error::other(
                "XSK is in another network namespace; run fdtop there",
            ));
        }
        let mut cookie = 0_u64;
        let mut len = 8;
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_COOKIE,
                (&mut cookie as *mut u64).cast(),
                &mut len,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        if self
            .at
            .is_none_or(|at| at.elapsed() >= Duration::from_secs(1))
        {
            self.at = Some(Instant::now());
            match dump() {
                Ok(values) => {
                    self.values = values;
                    self.error = None;
                }
                Err(error) => {
                    self.values.clear();
                    self.error = Some(error.to_string());
                }
            }
        }
        if let Some(error) = &self.error {
            return Err(io::Error::other(error.clone()));
        }
        let &(_, index, queue) = self
            .values
            .get(&cookie)
            .filter(|(found, _, _)| u64::from(*found) == inode)
            .ok_or_else(|| io::Error::other("XSK absent from diagnostic snapshot"))?;
        if index == 0 {
            return Ok("XSK unbound".into());
        }
        let mut name = [0; libc::IF_NAMESIZE];
        let ptr = unsafe { libc::if_indextoname(index, name.as_mut_ptr()) };
        let iface = if ptr.is_null() {
            format!("ifindex:{index}")
        } else {
            clean(unsafe { CStr::from_ptr(ptr) }.to_bytes())
        };
        Ok(format!("XSK {iface} q{queue} (ifindex {index})"))
    }
}

fn word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn parse(bytes: &[u8]) -> io::Result<(u64, (u32, u32, u32))> {
    if bytes.len() < 16 || bytes[0] != 44 {
        return Err(io::Error::other("invalid XDP diagnostic record"));
    }
    let cookie = u64::from(word(bytes, 8)) | (u64::from(word(bytes, 12)) << 32);
    let mut index = 0;
    let mut queue = 0;
    let mut at = 16;
    while at < bytes.len() {
        if bytes.len() - at < 4 {
            return Err(io::Error::other("truncated XDP diagnostic attribute"));
        }
        let len = u16::from_ne_bytes(bytes[at..at + 2].try_into().unwrap()) as usize;
        let kind = u16::from_ne_bytes(bytes[at + 2..at + 4].try_into().unwrap()) & 0x3fff;
        if len < 4 || at + len > bytes.len() {
            return Err(io::Error::other("invalid XDP diagnostic attribute"));
        }
        if kind == 1 {
            if len < 12 {
                return Err(io::Error::other("truncated XDP binding"));
            }
            index = word(bytes, at + 4);
            queue = word(bytes, at + 8);
        }
        at += (len + 3) & !3;
    }
    Ok((cookie, (word(bytes, 4), index, queue)))
}

fn dump() -> io::Result<HashMap<u64, (u32, u32, u32)>> {
    let fd = owned(unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_SOCK_DIAG,
        )
    })?;
    let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    kernel.nl_family = libc::AF_NETLINK as u16;
    if unsafe {
        libc::connect(
            fd.as_raw_fd(),
            (&kernel as *const libc::sockaddr_nl).cast(),
            std::mem::size_of_val(&kernel) as u32,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut request = [0_u8; 36];
    request[..4].copy_from_slice(&36_u32.to_ne_bytes());
    request[4..6].copy_from_slice(&20_u16.to_ne_bytes());
    request[6..8].copy_from_slice(&0x301_u16.to_ne_bytes());
    request[8..12].copy_from_slice(&1_u32.to_ne_bytes());
    request[16] = 44;
    request[24..28].copy_from_slice(&1_u32.to_ne_bytes()); // XDP_SHOW_INFO
    if unsafe { libc::send(fd.as_raw_fd(), request.as_ptr().cast(), request.len(), 0) }
        != request.len() as isize
    {
        return Err(io::Error::last_os_error());
    }
    let deadline = Instant::now() + Duration::from_millis(100);
    let mut values = HashMap::new();
    let mut buf = vec![0_u8; 65536];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "XDP diagnostic query timed out",
            ));
        }
        let mut poll = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut poll, 1, remaining.as_millis().max(1) as i32) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let size = unsafe {
            libc::recv(
                fd.as_raw_fd(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                libc::MSG_TRUNC | libc::MSG_DONTWAIT,
            )
        };
        if size < 0 {
            return Err(io::Error::last_os_error());
        }
        if size == 0 || size as usize > buf.len() {
            return Err(io::Error::other("truncated XDP diagnostic dump"));
        }
        let mut at = 0;
        while at < size as usize {
            if size as usize - at < 16 {
                return Err(io::Error::other("truncated netlink header"));
            }
            let len = word(&buf, at) as usize;
            if len < 16 || at + len > size as usize {
                return Err(io::Error::other("invalid netlink length"));
            }
            let kind = u16::from_ne_bytes(buf[at + 4..at + 6].try_into().unwrap());
            let flags = u16::from_ne_bytes(buf[at + 6..at + 8].try_into().unwrap());
            if word(&buf, at + 8) != 1 || flags & 0x10 != 0 {
                return Err(io::Error::other("interrupted XDP diagnostic dump"));
            }
            let payload = &buf[at + 16..at + len];
            match kind {
                2 | 3 => {
                    if payload.len() < 4 {
                        return Err(io::Error::other("truncated netlink status"));
                    }
                    let error = word(payload, 0) as i32;
                    if error != 0 {
                        if matches!(
                            -error,
                            libc::ENOENT | libc::EOPNOTSUPP | libc::EPROTONOSUPPORT
                        ) {
                            return Err(io::Error::other("XDP socket diagnostics unavailable; check CONFIG_XDP_SOCKETS_DIAG / xsk_diag module"));
                        }
                        return Err(io::Error::from_raw_os_error(error.saturating_neg()));
                    }
                    if kind == 3 {
                        return Ok(values);
                    }
                }
                20 => {
                    let (cookie, binding) = parse(payload)?;
                    values.insert(cookie, binding);
                }
                _ => return Err(io::Error::other("unexpected XDP diagnostic message")),
            }
            at += (len + 3) & !3;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn binding_and_truncation() {
        let mut bytes = [0_u8; 28];
        bytes[0] = 44;
        bytes[4..8].copy_from_slice(&123_u32.to_ne_bytes());
        bytes[8..12].copy_from_slice(&456_u32.to_ne_bytes());
        bytes[16..18].copy_from_slice(&12_u16.to_ne_bytes());
        bytes[18..20].copy_from_slice(&1_u16.to_ne_bytes());
        bytes[20..24].copy_from_slice(&7_u32.to_ne_bytes());
        bytes[24..28].copy_from_slice(&3_u32.to_ne_bytes());
        assert_eq!(parse(&bytes).unwrap(), (456, (123, 7, 3)));
        for length in [0, 8, 15, 17, 20, 27] {
            assert!(parse(&bytes[..length]).is_err());
        }
        assert_eq!(parse(&bytes[..16]).unwrap(), (456, (123, 0, 0)));
    }
}
