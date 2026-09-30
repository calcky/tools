use std::{fs, io};

#[derive(Clone, Copy, Debug, Default)]
pub struct Memory {
    pub rss: u64,
    pub anonymous: u64,
    pub file: u64,
    pub shmem: u64,
    pub private: u64,
    pub shared: u64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RuntimeMemory {
    pub heap_sys: u64,
    pub heap_released: u64,
    pub stack_inuse: u64,
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
        stack_inuse: value("Stack")?,
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
    let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
    let rollup = fs::read_to_string(format!("/proc/{pid}/smaps_rollup"))?;
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
    }

    #[test]
    fn parses_go_runtime_memory() {
        let text = "# HeapSys = 1000\n# HeapReleased = 200\n# Stack = 50 / 50\n# Sys = 1300\n";
        let runtime = parse_runtime(text).unwrap();
        assert_eq!(runtime.heap_sys - runtime.heap_released, 800);
        assert!(parse_runtime("# Sys = 1\n").is_err());
    }
}
