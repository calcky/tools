mod xsk;
use crate::{
    collect::{Identity, Key, Snapshot},
    model::{clean, Frame},
};
use std::{
    collections::HashMap,
    ffi::CStr,
    fs, io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddrV6},
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    os::unix::fs::MetadataExt,
    time::{Duration, Instant},
};

struct Cached {
    value: String,
    attempted: Instant,
    confirmed: Option<Instant>,
    error: Option<String>,
}

#[derive(Default)]
pub struct Resolver {
    entries: HashMap<Key, Cached>,
    xsk: xsk::Cache,
}

impl Resolver {
    pub fn describe(&mut self, fd: RawFd, id: &Identity) -> io::Result<String> {
        if id.family == 44 {
            self.xsk.name(fd, id.ino)
        } else {
            describe_socket(fd)
        }
    }
    pub fn enrich(&mut self, data: &mut Frame, snapshot: &Snapshot) {
        self.entries
            .retain(|key, _| snapshot.records.contains_key(key));
        let now = Instant::now();
        let mut processes: HashMap<u32, io::Result<OwnedFd>> = HashMap::new();
        for row in &mut data.rows {
            let id = &row.total.id;
            if id.key.object == 0 || matches!(id.kind, 3 | 7) {
                continue;
            }
            let entry = self.entries.entry(id.key).or_insert_with(|| Cached {
                value: row.object.clone(),
                attempted: now - Duration::from_secs(1),
                confirmed: None,
                error: None,
            });
            let mut live = false;
            if now.duration_since(entry.attempted) >= Duration::from_secs(1) {
                entry.attempted = now;
                let result = if id.kind == 2 {
                    let process = processes.entry(id.key.pid).or_insert_with(|| {
                        owned(unsafe { libc::syscall(libc::SYS_pidfd_open, id.key.pid, 0) as i32 })
                    });
                    match process {
                        Ok(process) => socket_name(process.as_raw_fd(), id, &mut self.xsk),
                        Err(error) => Err(io::Error::new(error.kind(), error.to_string())),
                    }
                } else {
                    path_name(id)
                };
                match result {
                    Ok(value) => {
                        entry.value = value;
                        entry.confirmed = Some(now);
                        entry.error = None;
                        live = true;
                    }
                    Err(error) => entry.error = Some(error.to_string()),
                }
            }
            row.object = entry.value.clone();
            row.metadata_source = if live {
                "live"
            } else if entry.confirmed.is_some() {
                "cached"
            } else {
                "observed"
            };
            row.metadata_age_ms = entry
                .confirmed
                .map(|at| now.duration_since(at).as_millis() as u64);
            row.metadata_error = entry.error.clone();
        }
    }
}

pub(crate) fn owned(fd: i32) -> io::Result<OwnedFd> {
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

pub(crate) fn matches(id: &Identity, inode: u64, dev: u64) -> bool {
    let encoded = ((libc::major(dev) as u64) << 20) | libc::minor(dev) as u64;
    inode == id.ino && encoded == id.dev as u64
}

fn mismatch() -> io::Error {
    io::Error::other("FD closed or reused; keeping observed metadata")
}

fn path_name(id: &Identity) -> io::Result<String> {
    let path = format!("/proc/{}/fd/{}", id.key.pid, id.key.fd);
    let before = fs::metadata(&path)?;
    if !matches(id, before.ino(), before.dev()) {
        return Err(mismatch());
    }
    let value = fs::read_link(&path)?;
    let after = fs::metadata(&path)?;
    if !matches(id, after.ino(), after.dev()) {
        return Err(mismatch());
    }
    Ok(clean(value.to_string_lossy().as_bytes()))
}

fn socket_name(process: RawFd, id: &Identity, xsk: &mut xsk::Cache) -> io::Result<String> {
    // A short-lived duplicate pins the socket while querying. No I/O or option
    // changes are performed on it. inode/device reject stale descriptor numbers.
    let fd = owned(unsafe { libc::syscall(libc::SYS_pidfd_getfd, process, id.key.fd, 0) as i32 })?;
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut stat) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if !matches(id, stat.st_ino, stat.st_dev) {
        return Err(mismatch());
    }
    if id.family == 44 {
        return xsk.name(fd.as_raw_fd(), id.ino);
    }
    describe_socket(fd.as_raw_fd())
}

fn address(fd: RawFd, peer: bool) -> io::Result<(libc::sockaddr_storage, usize)> {
    let mut value: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut size = std::mem::size_of_val(&value) as libc::socklen_t;
    let result = unsafe {
        if peer {
            libc::getpeername(
                fd,
                (&mut value as *mut libc::sockaddr_storage).cast(),
                &mut size,
            )
        } else {
            libc::getsockname(
                fd,
                (&mut value as *mut libc::sockaddr_storage).cast(),
                &mut size,
            )
        }
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if size as usize > std::mem::size_of_val(&value) {
        return Err(io::Error::other("truncated socket address"));
    }
    Ok((value, size as usize))
}

pub(crate) fn socket_option(fd: RawFd, option: i32) -> io::Result<i32> {
    let mut value = 0_i32;
    let mut size = std::mem::size_of_val(&value) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            option,
            (&mut value as *mut i32).cast(),
            &mut size,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(value)
}

fn describe_socket(fd: RawFd) -> io::Result<String> {
    let (local, size) = address(fd, false)?;
    let family = local.ss_family as i32;
    let mut local = format_address(&local, size)?;
    if family == libc::AF_NETLINK {
        local.push_str(&format!(
            " protocol={}",
            socket_option(fd, libc::SO_PROTOCOL)?
        ));
    }
    if socket_option(fd, libc::SO_ACCEPTCONN).unwrap_or(0) != 0 {
        return Ok(format!("{local} (listen)"));
    }
    let peer = match address(fd, true) {
        Ok((peer, size)) => format_address(&peer, size)?,
        Err(error) if error.raw_os_error() == Some(libc::ENOTCONN) => "unconnected".into(),
        Err(error) => return Err(error),
    };
    Ok(format!("{local} -> {peer}"))
}

fn format_address(value: &libc::sockaddr_storage, size: usize) -> io::Result<String> {
    match value.ss_family as i32 {
        libc::AF_INET if size >= std::mem::size_of::<libc::sockaddr_in>() => {
            let addr =
                unsafe { &*(value as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>() };
            Ok(format!(
                "{}:{}",
                Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes()),
                u16::from_be(addr.sin_port)
            ))
        }
        libc::AF_INET6 if size >= std::mem::size_of::<libc::sockaddr_in6>() => {
            let addr =
                unsafe { &*(value as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>() };
            Ok(SocketAddrV6::new(
                Ipv6Addr::from(addr.sin6_addr.s6_addr),
                u16::from_be(addr.sin6_port),
                0,
                addr.sin6_scope_id,
            )
            .to_string())
        }
        libc::AF_UNIX if size >= 2 => {
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    (value as *const libc::sockaddr_storage).cast::<u8>().add(2),
                    size - 2,
                )
            };
            Ok(format!("unix:{}", unix_name(bytes)))
        }
        libc::AF_NETLINK if size >= std::mem::size_of::<libc::sockaddr_nl>() => {
            let addr =
                unsafe { &*(value as *const libc::sockaddr_storage).cast::<libc::sockaddr_nl>() };
            Ok(format!(
                "netlink:pid={} groups=0x{:x}",
                addr.nl_pid, addr.nl_groups
            ))
        }
        _ => Err(io::Error::other("socket address family not decoded")),
    }
}

fn unix_name(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "unnamed".into();
    }
    if bytes[0] != 0 {
        return clean(bytes);
    }
    let mut name = String::from("@");
    for byte in &bytes[1..] {
        if (32..127).contains(byte) && *byte != b'\\' {
            name.push(*byte as char);
        } else {
            name.push_str(&format!("\\x{byte:02x}"));
        }
    }
    name
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        collect::Record,
        model::{frame, Filter},
    };

    fn file_identity(file: &fs::File) -> Identity {
        let stat = file.metadata().unwrap();
        Identity {
            key: Key {
                pid: std::process::id(),
                fd: file.as_raw_fd(),
                object: 1,
                ..Default::default()
            },
            ino: stat.ino(),
            dev: (libc::major(stat.dev()) << 20) | libc::minor(stat.dev()),
            kind: 1,
            ..Default::default()
        }
    }

    #[test]
    fn cache_retains_confirmed_path_on_failure_and_prunes_dead_objects() {
        let file = fs::File::open("/dev/null").unwrap();
        let id = file_identity(&file);
        let mut record = Record {
            id,
            ..Default::default()
        };
        record.rd.ops = 1;
        let snapshot = Snapshot {
            records: HashMap::from([(id.key, record)]),
            ..Default::default()
        };
        let mut resolver = Resolver::default();
        let mut data = frame(&Snapshot::default(), &snapshot, &Filter::default());
        resolver.enrich(&mut data, &snapshot);
        assert_eq!(data.rows[0].object, "/dev/null");
        assert_eq!(data.rows[0].metadata_source, "live");
        resolver.enrich(&mut data, &snapshot);
        assert_eq!(data.rows[0].metadata_source, "cached");
        // Mismatched inode deterministically models reuse without racing test threads.
        let mut reused = snapshot;
        reused.records.get_mut(&id.key).unwrap().id.ino += 1;
        resolver.entries.get_mut(&id.key).unwrap().attempted -= Duration::from_secs(2);
        let mut data = frame(&Snapshot::default(), &reused, &Filter::default());
        resolver.enrich(&mut data, &reused);
        assert_eq!(data.rows[0].object, "/dev/null");
        assert_eq!(data.rows[0].metadata_source, "cached");
        assert!(data.rows[0]
            .metadata_error
            .as_ref()
            .unwrap()
            .contains("reused"));
        let empty = Snapshot::default();
        resolver.enrich(&mut frame(&empty, &empty, &Filter::default()), &empty);
        assert!(resolver.entries.is_empty());
    }

    #[test]
    fn unix_names_and_tcp_ipv6_listener() {
        use std::os::linux::net::SocketAddrExt;
        use std::os::unix::net::{SocketAddr, UnixListener, UnixStream};
        let name = format!("fdtop-test-{}", std::process::id());
        let addr = SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
        let listener = UnixListener::bind_addr(&addr).unwrap();
        assert_eq!(
            describe_socket(listener.as_raw_fd()).unwrap(),
            format!("unix:@{name} (listen)")
        );
        let client = UnixStream::connect_addr(&addr).unwrap();
        let (server, _) = listener.accept().unwrap();
        assert_eq!(
            describe_socket(client.as_raw_fd()).unwrap(),
            format!("unix:unnamed -> unix:@{name}")
        );
        assert_eq!(
            describe_socket(server.as_raw_fd()).unwrap(),
            format!("unix:@{name} -> unix:unnamed")
        );
        let tcp = std::net::TcpListener::bind("[::1]:0").unwrap();
        assert_eq!(
            describe_socket(tcp.as_raw_fd()).unwrap(),
            format!("{} (listen)", tcp.local_addr().unwrap())
        );
    }
    #[test]
    fn unix_abstract_names_preserve_embedded_nuls() {
        assert_eq!(unix_name(b"\0a\0b"), "@a\\x00b");
        assert_eq!(unix_name(b"/tmp/test\0"), "/tmp/test");
        assert_eq!(unix_name(b""), "unnamed");
    }
    #[test]
    fn mismatched_fd_keeps_observed_metadata_with_error() {
        let file = fs::File::open("/dev/null").unwrap();
        let mut id = file_identity(&file);
        id.ino += 1;
        let mut record = Record {
            id,
            ..Default::default()
        };
        record.rd.ops = 1;
        let snapshot = Snapshot {
            records: HashMap::from([(id.key, record)]),
            ..Default::default()
        };
        let mut data = frame(&Snapshot::default(), &snapshot, &Filter::default());
        let original = data.rows[0].object.clone();
        Resolver::default().enrich(&mut data, &snapshot);
        assert_eq!(data.rows[0].object, original);
        assert_eq!(data.rows[0].metadata_source, "observed");
        assert!(data.rows[0].metadata_age_ms.is_none());
        assert!(data.rows[0].metadata_error.is_some());
    }
    #[test]
    fn udp_addresses_refresh_after_connect() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let first = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let second = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        assert!(describe_socket(socket.as_raw_fd())
            .unwrap()
            .contains("unconnected"));
        socket.connect(first.local_addr().unwrap()).unwrap();
        assert!(describe_socket(socket.as_raw_fd())
            .unwrap()
            .ends_with(&first.local_addr().unwrap().to_string()));
        socket.connect(second.local_addr().unwrap()).unwrap();
        assert!(describe_socket(socket.as_raw_fd())
            .unwrap()
            .ends_with(&second.local_addr().unwrap().to_string()));
    }
}
