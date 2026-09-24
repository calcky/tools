use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use super::{
    NicStatisticSemantics, NicStatistics, PrivateNicStatistic, StandardNicStatistic,
    StandardStatistic,
};

const ETHTOOL_GDRVINFO: u32 = 0x0000_0003;
const ETHTOOL_GSTRINGS: u32 = 0x0000_001b;
const ETHTOOL_GSTATS: u32 = 0x0000_001d;
const ETH_SS_STATS: u32 = 1;
const ETH_GSTRING_LEN: usize = 32;
const MAX_STATS: usize = 16_384;

// Linux UAPI ethtool_drvinfo.
#[repr(C)]
struct DriverInfo {
    command: u32,
    driver: [u8; 32],
    version: [u8; 32],
    firmware: [u8; 32],
    bus: [u8; 32],
    erom: [u8; 32],
    reserved: [u8; 12],
    private_flags: u32,
    statistics: u32,
    test_info_length: u32,
    eeprom_length: u32,
    register_length: u32,
}

#[derive(Debug)]
struct Buffer {
    pointer: *mut libc::c_void,
    length: usize,
    mapped_length: usize,
}

// The mapping is owned exclusively and only used through a mutable Context.
unsafe impl Send for Buffer {}

impl Buffer {
    fn new(length: usize) -> io::Result<Self> {
        // SAFETY: sysconf takes no pointers and _SC_PAGESIZE is supported on Linux.
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if page_size <= 0 {
            return Err(io::Error::last_os_error());
        }
        let page_size = page_size as usize;
        let writable = length.div_ceil(page_size) * page_size;
        let mapped_length = writable + page_size;
        // GSTRINGS/GSTATS can grow between queries. A trailing guard page makes
        // an oversized kernel copy fail with EFAULT instead of overwriting heap data.
        // SAFETY: anonymous mmap owns a new mapping; no existing mapping is replaced.
        let pointer = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                mapped_length,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if pointer == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let buffer = Self {
            pointer,
            length,
            mapped_length,
        };
        // SAFETY: the page-aligned writable prefix lies wholly within our mapping.
        if unsafe { libc::mprotect(pointer, writable, libc::PROT_READ | libc::PROT_WRITE) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(buffer)
    }

    fn bytes(&self) -> &[u8] {
        // SAFETY: anonymous mapped storage is initialized to zero and is readable for length bytes.
        unsafe { std::slice::from_raw_parts(self.pointer.cast(), self.length) }
    }

    fn set_u32(&mut self, offset: usize, value: u32) {
        // SAFETY: the mapping is writable and exclusively borrowed for length bytes.
        let bytes =
            unsafe { std::slice::from_raw_parts_mut(self.pointer.cast::<u8>(), self.length) };
        bytes[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
    }

    fn u32(&self, offset: usize) -> u32 {
        u32::from_ne_bytes(self.bytes()[offset..offset + 4].try_into().unwrap())
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        // SAFETY: this object exclusively owns the complete mapping, including its guard.
        unsafe {
            libc::munmap(self.pointer, self.mapped_length);
        }
    }
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid ethtool statistics")
}

fn query<T>(socket: &OwnedFd, interface: &str, data: *mut T) -> io::Result<()> {
    if !super::valid_interface_name(interface) {
        return Err(invalid());
    }
    // SAFETY: zero is a valid initial representation for the Linux ifreq union.
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    for (target, source) in request.ifr_name.iter_mut().zip(interface.bytes()) {
        *target = source as libc::c_char;
    }
    request.ifr_ifru.ifru_data = data.cast();
    // SAFETY: request contains a terminated interface name and a writable UAPI
    // buffer sized for the bounded number of statistics requested by the caller.
    if unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCETHTOOL as _, &mut request) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[derive(Debug, Default)]
pub(super) struct Context {
    socket: Option<OwnedFd>,
    names: Option<Buffer>,
    values: Option<Buffer>,
    schemas: BTreeMap<u32, NamedSchema>,
}

#[derive(Debug)]
struct NamedSchema {
    interface: String,
    schema: Schema,
}

#[derive(Debug)]
struct Schema {
    names: Vec<u8>,
    standard: Vec<(usize, StandardStatistic)>,
    private: Vec<(usize, String)>,
}

fn open_socket() -> io::Result<OwnedFd> {
    // SAFETY: socket has no pointer arguments and returns a new owned descriptor.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd was just created and has no other owner.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

impl Context {
    pub(super) fn channels(&mut self, interface: &str) -> io::Result<(u32, u32)> {
        if self.socket.is_none() {
            self.socket = Some(open_socket()?);
        }
        // Linux UAPI ethtool_channels: command, four maxima, four current counts.
        let mut data = [0_u32; 9];
        data[0] = 0x0000_003c; // ETHTOOL_GCHANNELS, read-only.
        query(
            self.socket.as_ref().expect("initialized above"),
            interface,
            data.as_mut_ptr(),
        )?;
        channel_counts(&data)
    }

    pub(super) fn settings(
        &mut self,
        interface: &str,
        operation: &str,
    ) -> io::Result<Vec<super::EthtoolSetting>> {
        // These fixed-layout legacy queries are used only after a generic
        // netlink EOPNOTSUPP, matching ethtool's compatibility fallback.
        let (command, words, fields): (u32, usize, &[(&str, usize, bool)]) = match operation {
            "-g" => (
                0x10,
                9,
                &[
                    ("Ring RX", 5, false),
                    ("Ring TX", 8, false),
                    ("Ring RX Max", 1, false),
                    ("Ring TX Max", 4, false),
                ],
            ),
            "-a" => (
                0x12,
                4,
                &[("Flow Control RX", 2, true), ("Flow Control TX", 3, true)],
            ),
            "-c" => (
                0x0e,
                23,
                &[
                    ("Adaptive RX", 10, true),
                    ("Adaptive TX", 11, true),
                    ("RX Usecs", 1, false),
                    ("RX Frames", 2, false),
                    ("TX Usecs", 5, false),
                    ("TX Frames", 6, false),
                ],
            ),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "native legacy query not implemented",
                ))
            }
        };
        if self.socket.is_none() {
            self.socket = Some(open_socket()?);
        }
        let mut data = [0_u32; 23];
        data[0] = command;
        debug_assert!(words <= data.len());
        query(
            self.socket.as_ref().expect("initialized above"),
            interface,
            data.as_mut_ptr(),
        )?;
        Ok(fields
            .iter()
            .map(|&(name, index, switch)| super::EthtoolSetting {
                name: name.to_owned(),
                value: if switch {
                    if data[index] == 0 { "off" } else { "on" }.to_owned()
                } else {
                    data[index].to_string()
                },
            })
            .collect())
    }

    pub(super) fn retain(&mut self, interfaces: &[super::NicInterface]) {
        let ordered = interfaces.windows(2).all(|pair| {
            (pair[0].ifindex, pair[0].interface.as_str())
                < (pair[1].ifindex, pair[1].interface.as_str())
        });
        self.schemas.retain(|index, cached| {
            if ordered {
                interfaces
                    .binary_search_by(|interface| {
                        (interface.ifindex, interface.interface.as_str())
                            .cmp(&(*index, cached.interface.as_str()))
                    })
                    .is_ok_and(|position| interfaces[position].hardware_backed)
            } else {
                interfaces.iter().any(|interface| {
                    interface.hardware_backed
                        && interface.ifindex == *index
                        && interface.interface == cached.interface
                })
            }
        });
    }

    pub(super) fn statistics(
        &mut self,
        interface: &str,
        ifindex: u32,
    ) -> io::Result<NicStatistics> {
        if self.socket.is_none() {
            self.socket = Some(open_socket()?);
        }
        let result = self.query_statistics(interface, ifindex);
        if result.is_err() {
            self.schemas.remove(&ifindex);
        }
        result
    }

    fn query_statistics(&mut self, interface: &str, ifindex: u32) -> io::Result<NicStatistics> {
        let socket = self.socket.as_ref().expect("socket initialized above");
        // SAFETY: DriverInfo contains only integers and byte arrays.
        let mut info: DriverInfo = unsafe { std::mem::zeroed() };
        info.command = ETHTOOL_GDRVINFO;
        query(socket, interface, &mut info)?;
        let count = info.statistics as usize;
        if count == 0 || count > MAX_STATS {
            return Err(invalid());
        }

        let names = reusable_buffer(&mut self.names, 12 + count * ETH_GSTRING_LEN)?;
        names.set_u32(0, ETHTOOL_GSTRINGS);
        names.set_u32(4, ETH_SS_STATS);
        names.set_u32(8, count as u32);
        query(socket, interface, names.pointer)?;
        if names.u32(8) as usize != count {
            return Err(invalid());
        }

        let values = reusable_buffer(&mut self.values, 8 + count * 8)?;
        values.set_u32(0, ETHTOOL_GSTATS);
        values.set_u32(4, count as u32);
        query(socket, interface, values.pointer)?;
        if values.u32(4) as usize != count {
            return Err(invalid());
        }
        // SAFETY: mmap is page-aligned, the 8-byte header preserves u64 alignment,
        // and the verified count fits the initialized writable mapping.
        let counters =
            unsafe { std::slice::from_raw_parts(values.pointer.cast::<u64>().add(1), count) };
        let raw_names = &names.bytes()[12..12 + count * ETH_GSTRING_LEN];
        decode_cached(&mut self.schemas, ifindex, interface, raw_names, counters)
    }
}

fn channel_counts(data: &[u32; 9]) -> io::Result<(u32, u32)> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "ethtool channel count overflow");
    Ok((
        data[5].checked_add(data[8]).ok_or_else(invalid)?,
        data[6].checked_add(data[8]).ok_or_else(invalid)?,
    ))
}

fn decode_cached(
    schemas: &mut BTreeMap<u32, NamedSchema>,
    ifindex: u32,
    interface: &str,
    raw_names: &[u8],
    counters: &[u64],
) -> io::Result<NicStatistics> {
    if raw_names.len() != counters.len() * ETH_GSTRING_LEN {
        schemas.remove(&ifindex);
        return Err(invalid());
    }
    // There is no UAPI schema generation. Count/driver/queue checks alone miss
    // same-count renames and reorders, so compare the names on every poll.
    if let Some(cached) = schemas.get(&ifindex) {
        if cached.interface == interface && cached.schema.names == raw_names {
            return Ok(cached.schema.decode(counters));
        }
    }
    schemas.remove(&ifindex);
    let schema = Schema::new(raw_names)?;
    let statistics = schema.decode(counters);
    schemas.insert(
        ifindex,
        NamedSchema {
            interface: interface.to_owned(),
            schema,
        },
    );
    Ok(statistics)
}

fn reusable_buffer(buffer: &mut Option<Buffer>, length: usize) -> io::Result<&mut Buffer> {
    if buffer.as_ref().is_none_or(|buffer| buffer.length < length) {
        *buffer = Some(Buffer::new(length)?);
    }
    Ok(buffer.as_mut().expect("buffer allocated above"))
}

#[cfg(test)]
fn decode(names: &[u8], values: &[u64]) -> io::Result<NicStatistics> {
    if names.len() != values.len() * ETH_GSTRING_LEN {
        return Err(invalid());
    }
    Ok(Schema::new(names)?.decode(values))
}

impl Schema {
    fn new(names: &[u8]) -> io::Result<Self> {
        let mut schema = Self {
            names: names.to_vec(),
            standard: Vec::new(),
            private: Vec::new(),
        };
        let mut seen = BTreeSet::new();
        for (index, name) in names.chunks_exact(ETH_GSTRING_LEN).enumerate() {
            let end = name
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(name.len());
            let name = std::str::from_utf8(&name[..end]).map_err(|_| invalid())?;
            if !super::valid_statistic_name(name.as_bytes()) || !seen.insert(name) {
                return Err(invalid());
            }
            if let Some(statistic) = StandardStatistic::from_name(name) {
                schema.standard.push((index, statistic));
            } else {
                schema.private.push((index, name.to_owned()));
            }
        }
        schema.standard.sort_by_key(|(_, statistic)| *statistic);
        schema
            .private
            .sort_by(|(_, left), (_, right)| left.cmp(right));
        Ok(schema)
    }

    fn decode(&self, values: &[u64]) -> NicStatistics {
        NicStatistics {
            standard: self
                .standard
                .iter()
                .map(|(index, statistic)| StandardNicStatistic {
                    statistic: *statistic,
                    value: values[*index],
                    semantics: NicStatisticSemantics::OpaqueCurrentOnly,
                })
                .collect(),
            private: self
                .private
                .iter()
                .map(|(index, name)| PrivateNicStatistic {
                    name: name.clone(),
                    value: values[*index],
                    semantics: NicStatisticSemantics::OpaqueCurrentOnly,
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(values: &[&str]) -> Vec<u8> {
        let mut bytes = vec![0; ETH_GSTRING_LEN * values.len()];
        for (slot, value) in bytes.chunks_exact_mut(ETH_GSTRING_LEN).zip(values) {
            slot[..value.len()].copy_from_slice(value.as_bytes());
        }
        bytes
    }

    #[test]
    fn channel_counts_use_current_rx_tx_plus_combined_and_reject_overflow() {
        assert_eq!(
            channel_counts(&[0x3c, 128, 128, 16, 128, 2, 3, 1, 4]).unwrap(),
            (6, 7)
        );
        assert_eq!(
            channel_counts(&[0x3c, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            (0, 0)
        );
        assert!(channel_counts(&[0x3c, 0, 0, 0, 0, u32::MAX, 0, 0, 1]).is_err());
    }

    #[test]
    fn binary_statistics_match_existing_text_semantics() {
        assert_eq!(std::mem::size_of::<DriverInfo>(), 196);
        let raw_names = names(&["rx_packets", "vendor_counter", "tx_errors"]);
        let actual = decode(&raw_names, &[17, u64::MAX, 3]).unwrap();
        let text = format!(
            "NIC statistics:\n rx_packets: 17\n vendor_counter: {}\n tx_errors: 3\n",
            u64::MAX
        );
        assert_eq!(
            actual,
            super::super::parse_ethtool_stats(text.as_bytes()).statistics
        );
    }

    #[test]
    fn inconsistent_or_malformed_driver_schema_falls_back_to_text() {
        assert!(decode(&names(&["rx_packets"]), &[]).is_err());
        assert!(decode(&names(&["rx_packets", "rx_packets"]), &[1, 2]).is_err());
        assert!(decode(&names(&["bad\nname"]), &[1]).is_err());
        assert!(decode(&names(&[""]), &[1]).is_err());
    }

    #[test]
    fn cached_schema_tracks_same_count_renames_and_reorders() {
        let mut schemas = BTreeMap::new();
        let key = 2;
        let initial = names(&["rx_packets", "vendor_counter"]);
        let first = decode_cached(&mut schemas, key, "eth0", &initial, &[5, 9]).unwrap();
        assert_eq!(first.standard[0].value, 5);
        let storage = schemas[&key].schema.names.as_ptr();
        let next = decode_cached(&mut schemas, key, "eth0", &initial, &[7, 11]).unwrap();
        assert_eq!(next.private[0].value, 11);
        assert_eq!(storage, schemas[&key].schema.names.as_ptr());
        let reordered = names(&["replacement_counter", "rx_packets"]);
        let next = decode_cached(&mut schemas, key, "eth0", &reordered, &[13, 17]).unwrap();
        assert_eq!(next.standard[0].value, 17);
        assert_eq!(next.private[0].name, "replacement_counter");
        assert_eq!(next.private[0].value, 13);
        assert!(decode_cached(
            &mut schemas,
            key,
            "eth0",
            &names(&["bad\nname", "rx_packets"]),
            &[0, 0]
        )
        .is_err());
        assert!(!schemas.contains_key(&key));
        assert_eq!(
            decode_cached(&mut schemas, key, "eth0", &names(&["rx_packets"]), &[19])
                .unwrap()
                .standard[0]
                .value,
            19
        );
    }

    #[test]
    fn cached_schema_does_not_survive_rename_or_invalid_replacement() {
        let mut schemas = BTreeMap::new();
        let initial = names(&["vendor_counter", "rx_packets"]);
        decode_cached(&mut schemas, 2, "eth0", &initial, &[3, 5]).unwrap();
        let renamed = decode_cached(&mut schemas, 2, "renamed0", &initial, &[7, 11]).unwrap();
        assert_eq!(schemas.len(), 1);
        assert_eq!(schemas[&2].interface, "renamed0");
        assert_eq!(renamed.private[0].value, 7);
        assert!(decode_cached(&mut schemas, 2, "eth0", &initial, &[1]).is_err());
        assert!(schemas.is_empty());
        let replacement = names(&["rx_packets", "replacement_counter"]);
        assert_eq!(
            decode_cached(&mut schemas, 2, "eth0", &replacement, &[13, 17]).unwrap(),
            decode(&replacement, &[13, 17]).unwrap()
        );
        assert!(decode_cached(
            &mut schemas,
            2,
            "eth0",
            &names(&["", "rx_packets"]),
            &[0, 0]
        )
        .is_err());
        assert!(schemas.is_empty());
    }

    #[test]
    fn schema_retention_tracks_identity_and_hardware_with_unordered_input() {
        let interface = |ifindex, name: &str, hardware_backed| super::super::NicInterface {
            ifindex,
            interface: name.to_owned(),
            hardware_backed,
            operstate: super::super::OperState::Up,
            sysfs: Default::default(),
            channels: Vec::new(),
            fallback_settings: Vec::new(),
            settings: super::super::EthtoolSettingsOutcome::NotHardwareInterface,
            ethtool: super::super::EthtoolOutcome::NotHardwareInterface,
        };
        for reverse in [false, true] {
            let mut context = Context::default();
            for index in 1..=5 {
                decode_cached(
                    &mut context.schemas,
                    index,
                    &format!("eth{index}"),
                    &names(&["rx_packets"]),
                    &[7],
                )
                .unwrap();
            }
            let mut current = vec![
                interface(1, "eth1", true),
                interface(2, "renamed2", true),
                interface(3, "eth3", false),
                interface(4, "eth4", true),
                interface(6, "eth5", true),
            ];
            if reverse {
                current.reverse();
            }
            context.retain(&current);
            assert_eq!(
                context.schemas.keys().copied().collect::<Vec<_>>(),
                vec![1, 4]
            );
        }
    }

    #[test]
    fn guarded_buffers_reuse_capacity_and_grow_without_losing_the_guard() {
        let mut buffer = None;
        let initial = reusable_buffer(&mut buffer, 128).unwrap().pointer;
        assert_eq!(reusable_buffer(&mut buffer, 64).unwrap().pointer, initial);
        let expanded = reusable_buffer(&mut buffer, 16384).unwrap();
        assert!(expanded.length >= 16384);
        assert!(expanded.mapped_length > expanded.length);
        let pointer = expanded.pointer;
        assert_eq!(
            reusable_buffer(&mut buffer, 16384).unwrap().pointer,
            pointer
        );
    }

    #[test]
    fn kernel_copy_cannot_cross_the_guard_page() {
        let buffer = Buffer::new(16).unwrap();
        let mut fds = [0; 2];
        // SAFETY: fds has room for both new pipe descriptors.
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        // SAFETY: each newly created descriptor has exactly one owner.
        let input = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let output = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        let bytes = [1_u8, 2];
        // SAFETY: the source covers two initialized bytes.
        assert_eq!(
            unsafe { libc::write(output.as_raw_fd(), bytes.as_ptr().cast(), 2) },
            2
        );
        // SAFETY: the pointer lies within our owned mapping. read performs checked
        // kernel user-copy; it must stop before the protected page, as ioctl does.
        let boundary = unsafe {
            buffer
                .pointer
                .cast::<u8>()
                .add(buffer.mapped_length / 2 - 1)
        };
        let copied = unsafe { libc::read(input.as_raw_fd(), boundary.cast(), 2) };
        assert!(
            copied == 1
                || (copied == -1
                    && io::Error::last_os_error().raw_os_error() == Some(libc::EFAULT))
        );
    }
}
