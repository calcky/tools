use std::{fs, io};

#[derive(Clone, Copy, Debug, Default)]
pub struct Memory {
    pub rss: u64,
    pub anonymous: u64,
    pub file: u64,
    pub shmem: u64,
    pub private: u64,
    pub shared: u64,
    pub detailed: bool,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RuntimeMemory {
    pub heap_sys: u64,
    pub heap_released: u64,
    pub stack_inuse: Option<u64>,
    pub sys: u64,
}

pub fn parse_runtime(text: &str) -> io::Result<RuntimeMemory> {
    let value = |key: &str| -> io::Result<u64> {
        let prefix = format!("# {key} = ");
        text.lines()
            .find_map(|line| line.strip_prefix(&prefix))
            .and_then(|value| value.split_whitespace().next())
            .and_then(|value| value.parse().ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("missing {key}")))
    };
    Ok(RuntimeMemory {
        heap_sys: value("HeapSys")?,
        heap_released: value("HeapReleased")?,
        stack_inuse: value("Stack").or_else(|_| value("StackInuse")).ok(),
        sys: value("Sys")?,
    })
}

fn field(text: &str, name: &str) -> io::Result<u64> {
    let line = text
        .lines()
        .find(|line| line.starts_with(name))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("missing {name}")))?;
    let kb: u64 = line[name.len()..]
        .split_whitespace()
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("empty {name}")))?
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, format!("invalid {name}")))?;
    Ok(kb.saturating_mul(1024))
}

pub fn read(pid: u32) -> io::Result<Memory> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("PID {pid} is not visible in this /proc: {error}"),
        )
    })?;
    let rollup = match fs::read_to_string(format!("/proc/{pid}/smaps_rollup")) {
        Ok(rollup) => rollup,
        Err(_) => return read_status(&status),
    };
    let rss = field(&rollup, "Rss:")?;
    let anonymous = field(&rollup, "Anonymous:")?;
    let shmem = field(&status, "RssShmem:")?;
    let private =
        field(&rollup, "Private_Clean:")?.saturating_add(field(&rollup, "Private_Dirty:")?);
    let shared = field(&rollup, "Shared_Clean:")?.saturating_add(field(&rollup, "Shared_Dirty:")?);
    Ok(Memory {
        rss,
        anonymous,
        file: rss.saturating_sub(anonymous).saturating_sub(shmem),
        shmem,
        private,
        shared,
        detailed: true,
    })
}

fn read_status(status: &str) -> io::Result<Memory> {
    Ok(Memory {
        rss: field(status, "VmRSS:")?,
        anonymous: field(status, "RssAnon:")?,
        file: field(status, "RssFile:")?,
        shmem: field(status, "RssShmem:")?,
        private: 0,
        shared: 0,
        detailed: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_kib_and_rejects_missing_fields() {
        assert_eq!(field("Rss: 423 kB\n", "Rss:").unwrap(), 423 * 1024);
        assert!(field("Size: 1 kB\n", "Rss:").is_err());
    }

    #[test]
    fn reads_current_process() {
        let memory = read(std::process::id()).unwrap();
        assert!(memory.rss > 0);
        assert!(memory.anonymous <= memory.rss);
        assert!(memory.detailed);
    }

    #[test]
    fn status_fallback_keeps_real_rss_without_smaps() {
        let memory = read_status(
            "VmRSS: 423000 kB\nRssAnon: 300000 kB\nRssFile: 120000 kB\nRssShmem: 3000 kB\n",
        )
        .unwrap();
        assert_eq!(memory.rss, 423000 * 1024);
        assert!(!memory.detailed);
        assert_eq!(memory.file, 120000 * 1024);
    }

    #[test]
    fn missing_pid_explains_namespace_visibility() {
        let error = read(u32::MAX).unwrap_err();
        assert!(error.to_string().contains("not visible in this /proc"));
    }

    #[test]
    fn parses_go_runtime_memory() {
        let text = "# HeapSys = 1000\n# HeapReleased = 200\n# Stack = 50 / 50\n# Sys = 1300\n";
        let runtime = parse_runtime(text).unwrap();
        assert_eq!(runtime.heap_sys - runtime.heap_released, 800);
        assert_eq!(runtime.stack_inuse, Some(50));
        assert_eq!(
            parse_runtime("# HeapSys = 1000\n# HeapReleased = 200\n# Sys = 1300\n")
                .unwrap()
                .stack_inuse,
            None
        );
        assert!(parse_runtime("# Sys = 1\n").is_err());
    }
}
