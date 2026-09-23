use crate::options::{Config, MAX_SOCKET_BUFFER};
use socket2::Socket;
use std::{collections::HashSet, io};

/// Validate host-dependent tuning before worker threads or traffic start.
/// This performs no affinity mutation.
pub fn validate(config: &Config) -> io::Result<()> {
    if let Some(cpus) = &config.cpus {
        if cpus.len() < config.workers {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "-A provides {} CPUs for {} workers; add CPUs or reduce -w",
                    cpus.len(),
                    config.workers
                ),
            ));
        }
        let allowed = allowed_cpus()?;
        if let Some(&cpu) = cpus.iter().find(|cpu| !allowed.contains(cpu)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("-A CPU {cpu} is not in the process affinity mask"),
            ));
        }
    }
    validate_buffer(config.send_buffer, "-S")?;
    validate_buffer(config.recv_buffer, "-D")?;
    Ok(())
}

/// Apply requested socket buffers. The kernel may report a larger effective
/// value because it accounts for socket overhead.
pub fn apply_socket(socket: &Socket, config: &Config) -> io::Result<()> {
    if let Some(bytes) = config.send_buffer {
        socket.set_send_buffer_size(bytes)?;
    }
    if let Some(bytes) = config.recv_buffer {
        socket.set_recv_buffer_size(bytes)?;
    }
    Ok(())
}

/// Return the kernel-reported effective `(send, receive)` sizes.
#[allow(dead_code)]
pub fn effective_buffers(socket: &Socket) -> io::Result<(usize, usize)> {
    Ok((socket.send_buffer_size()?, socket.recv_buffer_size()?))
}

/// Pin worker `id` once to its assigned CPU. Assignment never wraps.
pub fn pin_worker(config: &Config, id: usize) -> io::Result<()> {
    let Some(cpus) = &config.cpus else {
        return Ok(());
    };
    let Some(&cpu) = cpus.get(id) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("worker {id} has no CPU in -A assignment"),
        ));
    };
    let mut mask = empty_mask();
    // SAFETY: CPU_SET writes the requested bit in the initialized mask.
    unsafe { libc::CPU_SET(cpu, &mut mask) };
    // SAFETY: the pointer and exact mask size refer to the live local mask.
    let result =
        unsafe { libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mask) };
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn validate_buffer(value: Option<usize>, option: &str) -> io::Result<()> {
    if value.is_some_and(|bytes| bytes == 0 || bytes > MAX_SOCKET_BUFFER) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{option}: requested size is outside the supported range"),
        ));
    }
    Ok(())
}

fn empty_mask() -> libc::cpu_set_t {
    // SAFETY: an all-zero CPU set is an empty set.
    unsafe { std::mem::zeroed() }
}

fn allowed_cpus() -> io::Result<HashSet<usize>> {
    let mut mask = empty_mask();
    // SAFETY: sched_getaffinity writes into the initialized mask allocation.
    let result =
        unsafe { libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut mask) };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    let mut allowed = HashSet::new();
    for cpu in 0..std::mem::size_of::<libc::cpu_set_t>() * 8 {
        if unsafe { libc::CPU_ISSET(cpu, &mask) } {
            allowed.insert(cpu);
        }
    }
    Ok(allowed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn config(cpus: Option<Vec<usize>>, workers: usize) -> Config {
        Config {
            server: false,
            tcp: true,
            host: Some("127.0.0.1".into()),
            sessions: workers,
            warmup: Duration::from_secs(1),
            turnover: 0.0,
            pps: 1.0,
            length: 128,
            duration: Duration::from_secs(1),
            timeout: Duration::from_secs(1),
            workers,
            recording: "events".into(),
            cpus,
            send_buffer: None,
            recv_buffer: None,
            backlog: 4096,
            sources: Vec::new(),
            ports: (1, 2),
            reuse: None,
            port: 11112,
            ipv6: false,
            output: std::path::PathBuf::new(),
            analyze: None,
        }
    }

    #[test]
    fn validation_is_non_mutating_and_checks_worker_count() {
        let before = allowed_cpus().unwrap();
        let cpu = before.iter().next().copied().unwrap();
        assert!(validate(&config(Some(vec![cpu]), 2)).is_err());
        assert_eq!(allowed_cpus().unwrap(), before);
    }

    #[test]
    fn rejects_cpu_outside_current_mask() {
        let before = allowed_cpus().unwrap();
        if let Some(cpu) = (0..before.len().saturating_add(256)).find(|cpu| !before.contains(cpu)) {
            assert!(validate(&config(Some(vec![cpu]), 1)).is_err());
        }
        assert_eq!(allowed_cpus().unwrap(), before);
    }

    #[test]
    fn rejects_unassigned_worker_without_mutating_affinity() {
        let before = allowed_cpus().unwrap();
        let cpu = before.iter().next().copied().unwrap();
        assert!(pin_worker(&config(Some(vec![cpu]), 1), 1).is_err());
        assert_eq!(allowed_cpus().unwrap(), before);
    }

    #[test]
    fn rejects_invalid_socket_sizes() {
        for value in [Some(0), Some(MAX_SOCKET_BUFFER + 1)] {
            let mut config = config(None, 1);
            config.send_buffer = value;
            assert!(validate(&config).is_err());
        }
    }
}
