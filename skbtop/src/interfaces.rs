use anyhow::{bail, Context, Result};
use std::{
    collections::{BTreeMap, BTreeSet},
    io, mem,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

use crate::model::Interface;

#[derive(Clone, Debug)]
struct LinkInfo {
    index: u32,
    name: String,
    loopback: bool,
    deleted: bool,
}

pub struct Inventory {
    socket: OwnedFd,
    history: BTreeMap<(u32, u64), Interface>,
    current: BTreeMap<u32, (u64, bool)>,
    selected: BTreeSet<String>,
    generation: u64,
    pub gaps: u64,
}

impl Inventory {
    pub fn new(names: &[String]) -> Result<Self> {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error()).context("open interface discovery socket");
        }
        let socket = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut addr: libc::sockaddr_nl = unsafe { mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        addr.nl_groups = 1;
        let rc = unsafe {
            libc::bind(
                fd,
                (&addr as *const libc::sockaddr_nl).cast(),
                mem::size_of_val(&addr) as u32,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error()).context("subscribe to interface changes");
        }
        let timeout = libc::timeval {
            tv_sec: 2,
            tv_usec: 0,
        };
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&timeout as *const libc::timeval).cast(),
                mem::size_of_val(&timeout) as u32,
            );
        }
        let mut this = Self {
            socket,
            history: BTreeMap::new(),
            current: BTreeMap::new(),
            selected: names.iter().cloned().collect(),
            generation: 0,
            gaps: 0,
        };
        this.dump()?;
        for name in names {
            if !this.history.values().any(|i| i.alive && i.name == *name) {
                bail!("interface {name} not found in current network namespace");
            }
        }
        Ok(this)
    }

    fn dump(&mut self) -> Result<()> {
        let mut request = [0u8; 32];
        request[..4].copy_from_slice(&32u32.to_ne_bytes());
        request[4..6].copy_from_slice(&18u16.to_ne_bytes()); // RTM_GETLINK
        request[6..8].copy_from_slice(&0x301u16.to_ne_bytes());
        request[8..12].copy_from_slice(&1u32.to_ne_bytes());
        let mut addr: libc::sockaddr_nl = unsafe { mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        let rc = unsafe {
            libc::sendto(
                self.socket.as_raw_fd(),
                request.as_ptr().cast(),
                request.len(),
                0,
                (&addr as *const libc::sockaddr_nl).cast(),
                mem::size_of_val(&addr) as u32,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error()).context("request interface inventory");
        }
        loop {
            let (links, done) = self.receive(false)?;
            for link in links {
                self.apply(link);
            }
            if done {
                break;
            }
        }
        Ok(())
    }

    fn receive(&self, nonblocking: bool) -> Result<(Vec<LinkInfo>, bool)> {
        let mut bytes = vec![0u8; 262144];
        let n = unsafe {
            libc::recv(
                self.socket.as_raw_fd(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
                if nonblocking { libc::MSG_DONTWAIT } else { 0 },
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error()).context("receive interface changes");
        }
        parse(&bytes[..n as usize])
    }

    pub fn refresh(&mut self) -> Result<()> {
        loop {
            match self.receive(true) {
                Ok((links, _)) => {
                    for link in links {
                        self.apply(link);
                    }
                }
                Err(e)
                    if e.downcast_ref::<io::Error>()
                        .is_some_and(|e| e.kind() == io::ErrorKind::WouldBlock) =>
                {
                    break
                }
                Err(e)
                    if e.downcast_ref::<io::Error>()
                        .is_some_and(|e| e.raw_os_error() == Some(libc::ENOBUFS)) =>
                {
                    self.gaps += 1;
                    // A missed deletion could otherwise let an ifindex inherit old statistics.
                    for i in self.history.values_mut() {
                        i.alive = false;
                    }
                    self.current.clear();
                    self.dump()?;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn apply(&mut self, link: LinkInfo) {
        if link.deleted {
            if let Some((generation, _)) = self.current.remove(&link.index) {
                if let Some(i) = self.history.get_mut(&(link.index, generation)) {
                    i.alive = false;
                }
            }
            return;
        }
        let selected =
            !link.loopback && (self.selected.is_empty() || self.selected.contains(&link.name));
        let (generation, enabled) = *self.current.entry(link.index).or_insert_with(|| {
            self.generation += 1;
            (self.generation, selected)
        });
        self.current
            .insert(link.index, (generation, enabled || selected));
        self.history.insert(
            (link.index, generation),
            Interface {
                ifindex: link.index,
                generation,
                name: link.name,
                alive: true,
            },
        );
    }

    pub fn active(&self) -> Vec<(u32, u64, bool)> {
        self.current
            .iter()
            .map(|(&index, &(generation, enabled))| (index, generation, enabled))
            .collect()
    }
    pub fn all(&self) -> Vec<Interface> {
        self.history.values().cloned().collect()
    }
    pub fn label(&self, index: u32, generation: u64) -> String {
        if index == 0 {
            return "local".into();
        }
        self.history
            .get(&(index, generation))
            .map(|i| {
                if i.alive {
                    i.name.clone()
                } else {
                    format!("{} [gone]", i.name)
                }
            })
            .unwrap_or_else(|| format!("if#{index}@{generation}"))
    }
}

fn parse(bytes: &[u8]) -> Result<(Vec<LinkInfo>, bool)> {
    let mut links = Vec::new();
    let mut done = false;
    let mut offset = 0;
    while offset + 16 <= bytes.len() {
        let msg = &bytes[offset..];
        let len = u32::from_ne_bytes(msg[..4].try_into()?) as usize;
        if len < 16 || len > msg.len() {
            bail!("truncated interface netlink message");
        }
        let ty = u16::from_ne_bytes(msg[4..6].try_into()?);
        if ty == 3 {
            if u16::from_ne_bytes(msg[6..8].try_into()?) & 16 != 0 {
                bail!("interface inventory interrupted; retry startup");
            }
            done = true;
        }
        if ty == 2 && len >= 20 {
            let code = i32::from_ne_bytes(msg[16..20].try_into()?);
            if code != 0 {
                return Err(io::Error::from_raw_os_error(-code))
                    .context("interface inventory error");
            }
        }
        if ty == 4 {
            return Err(io::Error::from_raw_os_error(libc::ENOBUFS))
                .context("interface event overrun");
        }
        if (ty == 16 || ty == 17) && len >= 32 {
            let index = i32::from_ne_bytes(msg[20..24].try_into()?) as u32;
            let flags = u32::from_ne_bytes(msg[24..28].try_into()?);
            let mut name = None;
            let mut a = 32;
            while a + 4 <= len {
                let alen = u16::from_ne_bytes(msg[a..a + 2].try_into()?) as usize;
                if alen < 4 || a + alen > len {
                    bail!("truncated interface attribute");
                }
                if u16::from_ne_bytes(msg[a + 2..a + 4].try_into()?) & 0x3fff == 3 {
                    name = Some(
                        String::from_utf8_lossy(&msg[a + 4..a + alen])
                            .trim_end_matches('\0')
                            .to_owned(),
                    );
                }
                a += (alen + 3) & !3;
            }
            if let Some(name) = name {
                links.push(LinkInfo {
                    index,
                    name,
                    loopback: flags & libc::IFF_LOOPBACK as u32 != 0,
                    deleted: ty == 17,
                });
            }
        }
        offset += (len + 3) & !3;
    }
    Ok((links, done))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rename_keeps_generation_recreate_does_not() {
        let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC) };
        let mut i = Inventory {
            socket: unsafe { OwnedFd::from_raw_fd(fd) },
            history: BTreeMap::new(),
            current: BTreeMap::new(),
            selected: BTreeSet::from(["eth0".into()]),
            generation: 0,
            gaps: 0,
        };
        let link = |name: &str, deleted| LinkInfo {
            index: 4,
            name: name.into(),
            loopback: false,
            deleted,
        };
        i.apply(link("eth0", false));
        i.apply(link("new0", false));
        assert_eq!(i.active(), vec![(4, 1, true)]);
        assert_eq!(i.label(4, 1), "new0");
        i.apply(link("new0", true));
        i.apply(link("eth0", false));
        assert_eq!(i.active(), vec![(4, 2, true)]);
        assert_eq!(i.label(4, 1), "new0 [gone]");
        // Transmit keys use this namespace-wide identity without an ifindex.
        i.apply(LinkInfo {
            index: 5,
            name: "eth1".into(),
            loopback: false,
            deleted: false,
        });
        assert_eq!(i.active(), vec![(4, 2, true), (5, 3, false)]);
    }
    #[test]
    fn malformed_message_is_rejected() {
        assert!(parse(&[0u8; 16]).is_err());
    }
}
