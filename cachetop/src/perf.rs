use std::{
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

const TYPE_HARDWARE: u64 = 0;
const TYPE_SOFTWARE: u64 = 1;
const TYPE_HW_CACHE: u64 = 3;
const CPU_CYCLES: u64 = 0;
const INSTRUCTIONS: u64 = 1;
const CPU_MIGRATIONS: u64 = 4;
const CACHE_LL: u64 = 2;
const CACHE_READ_MISS: u64 = 1 << 16;
const FORMAT_TIME_ENABLED: u64 = 1;
const FORMAT_TIME_RUNNING: u64 = 2;
const FORMAT_GROUP: u64 = 8;
const FLAG_EXCLUDE_HV: u64 = 1 << 6;
const FLAG_CLOEXEC: libc::c_ulong = 8;

#[derive(Clone, Debug)]
pub struct Snapshot {
    pub counts: Vec<u64>,
    pub enabled: u64,
    pub running: u64,
    pub migrations: Option<u64>,
}

pub struct Group {
    leader: OwnedFd,
    _members: Vec<OwnedFd>,
    migrations: Option<OwnedFd>,
    pub llc: bool,
}

fn attr(kind: u64, config: u64, group: bool) -> [u64; 16] {
    let mut value = [0_u64; 16];
    value[0] = kind | (128_u64 << 32);
    value[1] = config;
    value[4] = if group {
        FORMAT_TIME_ENABLED | FORMAT_TIME_RUNNING | FORMAT_GROUP
    } else {
        0
    };
    value[5] = FLAG_EXCLUDE_HV;
    value
}

fn open(
    kind: u64,
    config: u64,
    pid: i32,
    cpu: i32,
    group_fd: i32,
    grouped: bool,
) -> io::Result<OwnedFd> {
    let value = attr(kind, config, grouped);
    let fd = unsafe {
        libc::syscall(
            libc::SYS_perf_event_open,
            value.as_ptr(),
            pid,
            cpu,
            group_fd,
            FLAG_CLOEXEC,
        ) as i32
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

impl Group {
    fn open_with(pid: i32, cpu: i32, llc: bool) -> io::Result<Self> {
        let leader = open(TYPE_HARDWARE, CPU_CYCLES, pid, cpu, -1, true)?;
        let mut members = vec![open(
            TYPE_HARDWARE,
            INSTRUCTIONS,
            pid,
            cpu,
            leader.as_raw_fd(),
            true,
        )?];
        if llc {
            for config in [CACHE_LL, CACHE_LL | CACHE_READ_MISS] {
                members.push(open(
                    TYPE_HW_CACHE,
                    config,
                    pid,
                    cpu,
                    leader.as_raw_fd(),
                    true,
                )?);
            }
        }
        let migrations = open(TYPE_SOFTWARE, CPU_MIGRATIONS, pid, cpu, -1, false).ok();
        Ok(Self {
            leader,
            _members: members,
            migrations,
            llc,
        })
    }

    pub fn open_best(pid: i32, cpu: i32) -> io::Result<Self> {
        match Self::open_with(pid, cpu, true) {
            Ok(group) => Ok(group),
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(libc::EINVAL | libc::ENOENT | libc::EOPNOTSUPP)
                ) =>
            {
                Self::open_with(pid, cpu, false)
            }
            Err(error) => Err(error),
        }
    }

    pub fn read(&self) -> io::Result<Snapshot> {
        let expected = 3 + 1 + self._members.len();
        let mut data = [0_u64; 7];
        let bytes = expected * std::mem::size_of::<u64>();
        let actual =
            unsafe { libc::read(self.leader.as_raw_fd(), data.as_mut_ptr().cast(), bytes) };
        if actual != bytes as isize || data[0] != (expected - 3) as u64 {
            return Err(if actual < 0 {
                io::Error::last_os_error()
            } else {
                io::Error::new(io::ErrorKind::UnexpectedEof, "short perf group read")
            });
        }
        let migrations = self.migrations.as_ref().and_then(|fd| {
            let mut count = 0_u64;
            let actual = unsafe { libc::read(fd.as_raw_fd(), (&mut count as *mut u64).cast(), 8) };
            (actual == 8).then_some(count)
        });
        Ok(Snapshot {
            counts: data[3..expected].to_vec(),
            enabled: data[1],
            running: data[2],
            migrations,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_layout_and_llc_definition() {
        let event = attr(TYPE_HW_CACHE, CACHE_LL | CACHE_READ_MISS, true);
        assert_eq!(event[0], (128_u64 << 32) | TYPE_HW_CACHE);
        assert_eq!(event[1], 0x10002);
        assert_eq!(
            event[4],
            FORMAT_TIME_ENABLED | FORMAT_TIME_RUNNING | FORMAT_GROUP
        );
    }
}
