use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, ValueEnum};
use libbpf_rs::btf::{types::Func, Btf};
use libbpf_rs::{MapCore, MapFlags, Object, ObjectBuilder, PerfBufferBuilder};
use pktbaffle::{LinkType, Target};
use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::fs::{self, File};
use std::io::BufWriter;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use xpcap::event::{Event, Stage};
use xpcap::filter;
use xpcap::packet::PacketSocket;
use xpcap::pcapng::PcapngWriter;

const BPF_OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/capture.bpf.o"));
const MAX_IFACES: usize = 16;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
enum Direction {
    In,
    Out,
    #[default]
    Inout,
}

#[derive(Clone, Copy)]
struct Selection {
    mask: u32,
    pcap_in: bool,
    pcap_out: bool,
}

#[derive(Clone, Copy, Default)]
struct PrintOptions {
    verbose: bool,
    link_header: bool,
}

#[derive(Parser, Debug)]
#[command(
    version,
    about = "Capture XSK and PCAP packets, with optional XDP/redirect stages",
    after_help = "Filter examples (tcpdump syntax):\n  xpcap -i any tcp and port 443\n  xpcap -i eth0 udp and dst port 53\n  xpcap -i eth0 -S xsk host 192.0.2.1 and port 9000"
)]
struct Args {
    #[arg(
        short = 'i',
        required = true,
        value_name = "IFACE",
        help = "Interface (repeatable), or any for all interfaces"
    )]
    interfaces: Vec<String>,
    #[arg(short = 'w', value_name = "FILE", help = "Also write PCAPNG to FILE")]
    write: Option<PathBuf>,
    #[arg(
        short = 'v',
        help = "Show IP header details (TTL, ID, flags, checksum)"
    )]
    verbose: bool,
    #[arg(
        short = 'e',
        help = "Show link header (Ethernet/VLAN, or cooked SLL for any)"
    )]
    link_header: bool,
    #[arg(
        short = 'S',
        long,
        value_name = "LIST",
        help = "Stages: xsk,pcap,xdp-in,xdp-out,redirect (comma-separated)"
    )]
    stage: Option<String>,
    #[arg(short = 'Q', value_enum, default_value_t = Direction::Inout, value_name = "DIRECTION", help = "Capture direction")]
    direction: Direction,
    #[arg(
        short = 'q',
        long,
        value_name = "QUEUE",
        help = "XDP/XSK queue (not PCAP)"
    )]
    queue: Option<u32>,
    #[arg(
        short = 'c',
        value_name = "EVENTS",
        help = "Stop after EVENTS across all stages"
    )]
    count: Option<u64>,
    #[arg(short = 'T', value_name = "SECONDS", help = "Stop after SECONDS")]
    duration: Option<u64>,
    #[arg(short = 's', default_value_t = 2048, value_parser = clap::value_parser!(u32).range(1..=9216), help = "Captured bytes per packet (1-9216)")]
    snaplen: u32,
    #[arg(short = 'm', long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..), help = "Keep about one in N matching packets per stage")]
    sample: u32,
    #[arg(short = 'B', long = "perf-pages", default_value_t = 256, value_parser = clap::value_parser!(usize), help = "Perf buffer pages per CPU (power of two)")]
    buffer_pages: usize,
    #[arg(
        value_name = "FILTER",
        trailing_var_arg = true,
        help = "Tcpdump-style packet filter"
    )]
    filter: Vec<String>,
}

fn selection(args: &Args) -> Result<Selection> {
    let mut selected = Selection {
        mask: 0,
        pcap_in: false,
        pcap_out: false,
    };
    if let Some(stages) = &args.stage {
        for name in stages.split(',').map(str::trim) {
            match name {
                "xsk" => selected.mask |= Stage::XskRx.bit() | Stage::XskTx.bit(),
                "xsk-in" | "xsk-rx" => selected.mask |= Stage::XskRx.bit(),
                "xsk-out" | "xsk-tx" => selected.mask |= Stage::XskTx.bit(),
                "pcap" => {
                    selected.pcap_in = true;
                    selected.pcap_out = true;
                }
                "pcap-in" => selected.pcap_in = true,
                "pcap-out" => selected.pcap_out = true,
                "xdp-in" => selected.mask |= Stage::XdpIn.bit(),
                "xdp-out" => selected.mask |= Stage::XdpOut.bit(),
                "redirect" => selected.mask |= Stage::Redirect.bit(),
                _ => bail!("unknown stage: {name}"),
            }
        }
    } else {
        selected.mask = Stage::XskRx.bit() | Stage::XskTx.bit();
        selected.pcap_in = true;
        selected.pcap_out = true;
    }
    match args.direction {
        Direction::In => {
            selected.mask &= !Stage::XskTx.bit();
            selected.pcap_out = false;
        }
        Direction::Out => {
            selected.mask &= Stage::XskTx.bit();
            selected.pcap_in = false;
        }
        Direction::Inout => {}
    }
    if selected.pcap_in || selected.pcap_out {
        selected.mask |= Stage::Pcap.bit();
    } else {
        selected.mask &= !Stage::Pcap.bit();
    }
    if selected.mask == 0 {
        bail!("no stages remain after --stage and -Q selection");
    }
    Ok(selected)
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Config {
    stage_mask: u32,
    snaplen: u32,
    ifindexes: [u32; MAX_IFACES],
    ifcount: u32,
    queue: u32,
    has_queue: u32,
    prog_id: u32,
    sample: u32,
}

impl Config {
    fn bytes(&self) -> &[u8] {
        // repr(C) matches capture_config; every byte starts initialized to zero.
        unsafe {
            std::slice::from_raw_parts((self as *const Self).cast(), std::mem::size_of::<Self>())
        }
    }
}

fn build_config(args: &Args) -> Result<(Config, HashMap<u32, String>, Selection)> {
    let any = capture_any(args);
    if args.interfaces.iter().any(|name| name == "any") && !any {
        bail!("-i any cannot be combined with other interfaces");
    }
    if args.interfaces.len() > MAX_IFACES {
        bail!("at most {MAX_IFACES} interfaces are supported");
    }
    if !args.buffer_pages.is_power_of_two() || args.buffer_pages < 2 {
        bail!("--perf-pages must be a power of two, at least 2");
    }
    if args.write.as_deref() == Some(std::path::Path::new("-")) {
        bail!("-w requires a file path, not stdout");
    }
    let mut config = Config {
        snaplen: args.snaplen,
        sample: args.sample,
        ..Config::default()
    };
    let mut names = HashMap::new();
    let interface_names = if any {
        let mut found = Vec::new();
        for entry in fs::read_dir("/sys/class/net").context("enumerate interfaces")? {
            found.push(entry?.file_name().to_string_lossy().into_owned());
        }
        found.sort();
        found
    } else {
        args.interfaces.clone()
    };
    for name in &interface_names {
        let c_name = CString::new(name.as_str()).context("interface contains NUL")?;
        let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
        if index == 0 {
            if any {
                continue;
            }
            bail!("interface {name} not found");
        }
        if names.insert(index, name.clone()).is_none() && !any {
            config.ifindexes[config.ifcount as usize] = index;
            config.ifcount += 1;
        }
    }
    let selected = selection(args)?;
    config.stage_mask = selected.mask;
    if let Some(queue) = args.queue {
        config.queue = queue;
        config.has_queue = 1;
    }
    Ok((config, names, selected))
}

fn capture_any(args: &Args) -> bool {
    args.interfaces.len() == 1 && args.interfaces[0] == "any"
}

fn interface_name(ifindex: u32) -> String {
    let mut buffer = [0; libc::IF_NAMESIZE];
    let name = unsafe { libc::if_indextoname(ifindex, buffer.as_mut_ptr()) };
    if name.is_null() {
        format!("ifindex-{ifindex}")
    } else {
        unsafe { CStr::from_ptr(name) }
            .to_string_lossy()
            .into_owned()
    }
}

struct Loaded {
    _object: Object,
    _links: Vec<libbpf_rs::Link>,
}

#[derive(Default)]
struct StageCoverage {
    attached: Vec<String>,
    missing: Vec<String>,
}

struct Coverage {
    stages: [StageCoverage; 6],
}

impl Coverage {
    fn new() -> Self {
        Self {
            stages: std::array::from_fn(|_| StageCoverage::default()),
        }
    }

    fn attached(&mut self, stage: Stage, path: impl Into<String>) {
        self.stages[stage as usize - 1].attached.push(path.into());
    }

    fn missing(&mut self, stage: Stage, path: impl Into<String>) {
        self.stages[stage as usize - 1].missing.push(path.into());
    }

    fn status(&self, stage: Stage) -> &'static str {
        let row = &self.stages[stage as usize - 1];
        if row.attached.is_empty() {
            "unavailable"
        } else if row.missing.is_empty() {
            "ready"
        } else {
            "degraded"
        }
    }

    fn print(&self, mask: u32) {
        println!("Capture coverage:");
        for stage in Stage::ALL {
            if mask & stage.bit() == 0 {
                continue;
            }
            let row = &self.stages[stage as usize - 1];
            let paths = if row.attached.is_empty() {
                "none".to_string()
            } else {
                row.attached.join(", ")
            };
            println!("  {:<9} {:<11} {paths}", stage.name(), self.status(stage));
        }
    }
}

fn kernel_stats(loaded: &[Loaded]) -> Result<[[u64; 6]; 5]> {
    let mut result = [[0u64; 6]; 5];
    for item in loaded {
        let map = item
            ._object
            .maps()
            .find(|map| map.name() == "stats")
            .ok_or_else(|| anyhow!("stats map missing"))?;
        for (stage, counters) in result.iter_mut().enumerate() {
            for (reason, total) in counters.iter_mut().enumerate() {
                let key = (stage * 6 + reason) as u32;
                if let Some(per_cpu) = map.lookup_percpu(&key.to_ne_bytes(), MapFlags::ANY)? {
                    for value in per_cpu {
                        *total += u64::from_ne_bytes(
                            value
                                .as_slice()
                                .try_into()
                                .map_err(|_| anyhow!("invalid stats value"))?,
                        );
                    }
                }
            }
        }
    }
    Ok(result)
}

fn load_group(
    names: &[&str],
    config: &Config,
    filter_value: &[u8],
    target: Option<(i32, &str)>,
    shared_events: Option<&Object>,
) -> Result<Loaded> {
    let mut open = ObjectBuilder::default().open_memory(BPF_OBJECT)?;
    for mut program in open.progs_mut() {
        let name = program.name().to_string_lossy();
        let enabled = names.iter().any(|candidate| *candidate == name);
        program.set_autoload(enabled);
        if enabled && (name == "xdp_entry" || name == "xdp_exit") {
            let (fd, function) = target.ok_or_else(|| anyhow!("XDP target missing"))?;
            program.set_attach_target(fd, Some(function.to_string()))?;
        }
    }
    if let Some(shared) = shared_events {
        for name in ["events", "redirect_scratch"] {
            let fd = shared
                .maps()
                .find(|map| map.name() == name)
                .ok_or_else(|| anyhow!("shared {name} map missing"))?;
            let mut map = open
                .maps_mut()
                .find(|map| map.name() == name)
                .ok_or_else(|| anyhow!("{name} map missing"))?;
            map.reuse_fd(fd.as_fd())?;
        }
    }
    let object = open.load()?;
    object
        .maps()
        .find(|map| map.name() == "config")
        .ok_or_else(|| anyhow!("config map missing"))?
        .update(&0u32.to_ne_bytes(), config.bytes(), MapFlags::ANY)?;
    object
        .maps()
        .find(|map| map.name() == "capture_filter")
        .ok_or_else(|| anyhow!("capture filter map missing"))?
        .update(&0u32.to_ne_bytes(), filter_value, MapFlags::ANY)?;
    let mut links = Vec::new();
    for program in object.progs_mut() {
        if names
            .iter()
            .any(|candidate| *candidate == program.name().to_string_lossy())
        {
            let link = if program.name().to_string_lossy().starts_with("redirect_")
                && (program.name() == "redirect_trace" || program.name() == "redirect_error_trace")
            {
                let event = if program.name() == "redirect_trace" {
                    "xdp_redirect"
                } else {
                    "xdp_redirect_err"
                };
                program.attach_tracepoint(libbpf_rs::TracepointCategory::Xdp, event)?
            } else {
                program.attach_trace()?
            };
            links.push(link);
        }
    }
    Ok(Loaded {
        _object: object,
        _links: links,
    })
}

fn xdp_program_id(ifindex: u32) -> Result<Option<u32>> {
    let mut id = 0;
    let result = unsafe { libbpf_sys::bpf_xdp_query_id(ifindex as i32, 0, &mut id) };
    if result != 0 {
        bail!("XDP query failed for ifindex {ifindex}: {result}");
    }
    Ok((id != 0).then_some(id))
}

fn xdp_chain_ids(main_id: u32) -> Result<Vec<u32>> {
    let mut ids = vec![main_id];
    let mut cursor = 0;
    loop {
        let mut next = 0;
        if unsafe { libbpf_sys::bpf_link_get_next_id(cursor, &mut next) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ENOENT) {
                break;
            }
            return Err(error).context("enumerate BPF links");
        }
        cursor = next;
        let link_fd = unsafe { libbpf_sys::bpf_link_get_fd_by_id(next) };
        if link_fd < 0 {
            continue;
        }
        let link_fd = unsafe { OwnedFd::from_raw_fd(link_fd) };
        let mut link: libbpf_sys::bpf_link_info = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of_val(&link) as u32;
        if unsafe {
            libbpf_sys::bpf_obj_get_info_by_fd(
                link_fd.as_raw_fd(),
                (&mut link as *mut libbpf_sys::bpf_link_info).cast(),
                &mut len,
            )
        } != 0
            || link.type_ != libbpf_sys::BPF_LINK_TYPE_TRACING
            || unsafe { link.__bindgen_anon_1.tracing.target_obj_id } != main_id
        {
            continue;
        }
        let prog_fd = unsafe { libbpf_sys::bpf_prog_get_fd_by_id(link.prog_id) };
        if prog_fd < 0 {
            continue;
        }
        let prog_fd = unsafe { OwnedFd::from_raw_fd(prog_fd) };
        let mut prog: libbpf_sys::bpf_prog_info = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of_val(&prog) as u32;
        if unsafe {
            libbpf_sys::bpf_obj_get_info_by_fd(
                prog_fd.as_raw_fd(),
                (&mut prog as *mut libbpf_sys::bpf_prog_info).cast(),
                &mut len,
            )
        } == 0
            && prog.type_ == libbpf_sys::BPF_PROG_TYPE_EXT
        {
            ids.push(prog.id);
        }
    }
    ids.sort_unstable();
    ids.dedup();
    Ok(ids)
}

fn xdp_target(id: u32) -> Result<(OwnedFd, String)> {
    let fd = unsafe { libbpf_sys::bpf_prog_get_fd_by_id(id) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("open XDP program");
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut info: libbpf_sys::bpf_prog_info = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of_val(&info) as u32;
    let result = unsafe {
        libbpf_sys::bpf_obj_get_info_by_fd(
            fd.as_raw_fd(),
            (&mut info as *mut libbpf_sys::bpf_prog_info).cast(),
            &mut len,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error()).context("read XDP program info");
    }
    if info.btf_id == 0 || info.nr_func_info == 0 {
        bail!("XDP program {id} has no function BTF for fentry/fexit");
    }

    let mut first_func = libbpf_sys::bpf_func_info::default();
    let mut query = libbpf_sys::bpf_prog_info {
        func_info_rec_size: std::mem::size_of::<libbpf_sys::bpf_func_info>() as u32,
        func_info: (&mut first_func as *mut libbpf_sys::bpf_func_info) as u64,
        nr_func_info: 1,
        ..Default::default()
    };
    let mut len = std::mem::size_of_val(&query) as u32;
    if unsafe {
        libbpf_sys::bpf_obj_get_info_by_fd(
            fd.as_raw_fd(),
            (&mut query as *mut libbpf_sys::bpf_prog_info).cast(),
            &mut len,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error()).context("read XDP function info");
    }
    if query.nr_func_info == 0 || first_func.insn_off != 0 {
        bail!("XDP program {id} has no entry function info");
    }
    let btf = Btf::from_prog_id(id).context("load XDP program BTF")?;
    let name = btf_func_name(&btf, first_func.type_id)?;
    Ok((fd, name))
}

fn btf_func_name(btf: &Btf<'_>, type_id: u32) -> Result<String> {
    let func = btf
        .type_by_id::<Func<'_>>(type_id.into())
        .ok_or_else(|| anyhow!("BTF type {type_id} is not a function"))?;
    Ok(func
        .name()
        .ok_or_else(|| anyhow!("BTF function {type_id} has no name"))?
        .to_string_lossy()
        .into_owned())
}

fn redirect_map_type(id: u32) -> String {
    if id == i32::MAX as u32 {
        return "map-type=direct".into();
    }
    if id == 0 {
        return "map-type=unknown".into();
    }
    let fd = unsafe { libbpf_sys::bpf_map_get_fd_by_id(id) };
    if fd < 0 {
        return "map-type=unavailable".into();
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut info: libbpf_sys::bpf_map_info = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of_val(&info) as u32;
    if unsafe {
        libbpf_sys::bpf_obj_get_info_by_fd(
            fd.as_raw_fd(),
            (&mut info as *mut libbpf_sys::bpf_map_info).cast(),
            &mut len,
        )
    } != 0
    {
        return "map-type=unavailable".into();
    }
    let kind = match info.type_ {
        libbpf_sys::BPF_MAP_TYPE_XSKMAP => "XSKMAP",
        libbpf_sys::BPF_MAP_TYPE_DEVMAP => "DEVMAP",
        libbpf_sys::BPF_MAP_TYPE_DEVMAP_HASH => "DEVMAP_HASH",
        libbpf_sys::BPF_MAP_TYPE_CPUMAP => "CPUMAP",
        _ => "other",
    };
    format!("map-type={kind}")
}

fn wall_offset_ns() -> Result<i128> {
    let mut mono: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut mono) } != 0 {
        return Err(std::io::Error::last_os_error()).context("clock_gettime");
    }
    let wall = SystemTime::now().duration_since(UNIX_EPOCH)?;
    Ok(wall.as_nanos() as i128 - (mono.tv_sec as i128 * 1_000_000_000 + mono.tv_nsec as i128))
}

fn local_time(ns: u64) -> String {
    // musl uses a 64-bit time_t even on ARMv7; the storage must match its C ABI.
    let seconds = (ns / 1_000_000_000) as i64;
    let mut time: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::localtime_r((&seconds as *const i64).cast(), &mut time) };
    format!(
        "{:02}:{:02}:{:02}.{:09}",
        time.tm_hour,
        time.tm_min,
        time.tm_sec,
        ns % 1_000_000_000
    )
}

fn format_capture_line(
    names: &HashMap<u32, String>,
    show_interface: bool,
    options: PrintOptions,
    event: &Event<'_>,
    wall: u64,
    extra: &str,
) -> String {
    let interface = if show_interface {
        format!(
            "{:<12} ",
            names.get(&event.ifindex).map(String::as_str).unwrap_or("?")
        )
    } else {
        String::new()
    };
    let queue = if event.stage == Stage::Pcap || event.queue == u32::MAX {
        "q-".to_string()
    } else {
        format!("q{}", event.queue)
    };
    let (source, direction) = match event.stage {
        Stage::XskRx => ("XSK", "IN"),
        Stage::XskTx => ("XSK", "OUT"),
        Stage::Pcap if event.action == 1 => ("PCAP", "OUT"),
        Stage::Pcap => ("PCAP", "IN"),
        Stage::XdpIn => ("XDP-IN", "IN"),
        Stage::XdpOut => ("XDP-OUT", "IN"),
        Stage::Redirect => ("REDIRECT", "IN"),
    };
    let suffix = if extra.is_empty() {
        String::new()
    } else {
        format!(" {extra}")
    };
    let link = if options.link_header {
        event.link_detail()
    } else {
        String::new()
    };
    format!(
        "{} {}{:<4} {:<8} {:<3} {}{}{}{}",
        local_time(wall),
        interface,
        queue,
        source,
        direction,
        link,
        event.terminal_detail_with_options(options.verbose),
        if event.packet.len() < event.packet_len as usize {
            format!(" (captured {})", event.packet.len())
        } else {
            String::new()
        },
        suffix
    )
}

struct CaptureState {
    names: HashMap<u32, String>,
    show_interface: bool,
    print_options: PrintOptions,
    map_types: HashMap<u32, String>,
    writer: Option<PcapngWriter<BufWriter<File>>>,
    offset: i128,
    counts: [u64; 6],
    total: u64,
    lost: u64,
    invalid: u64,
    limit: Option<u64>,
    error: Option<String>,
}

impl CaptureState {
    fn sample(&mut self, data: &[u8]) {
        if self.limit.is_some_and(|limit| self.total >= limit) {
            return;
        }
        let event = match Event::parse(data) {
            Ok(event) => event,
            Err(error) => {
                self.invalid += 1;
                if self.invalid <= 3 {
                    eprintln!(
                        "invalid perf event: {error:#}; len={} header={:02x?}",
                        data.len(),
                        &data[..data.len().min(48)]
                    );
                }
                return;
            }
        };
        self.record(event);
    }

    fn record(&mut self, event: Event<'_>) {
        if self.limit.is_some_and(|limit| self.total >= limit) {
            return;
        }
        self.names
            .entry(event.ifindex)
            .or_insert_with(|| interface_name(event.ifindex));
        let wall = (event.ts_ns as i128 + self.offset).max(0) as u64;
        let extra = if event.stage == Stage::Redirect
            && event.flags & xpcap::event::FLAG_REDIRECT_META != 0
        {
            self.map_types
                .entry(event.map_id)
                .or_insert_with(|| redirect_map_type(event.map_id))
                .as_str()
        } else {
            ""
        };
        println!(
            "{}",
            format_capture_line(
                &self.names,
                self.show_interface,
                self.print_options,
                &event,
                wall,
                extra,
            )
        );
        if let Some(writer) = &mut self.writer {
            if event.flags & xpcap::event::FLAG_COOKED == 0 {
                let name = &self.names[&event.ifindex];
                if let Err(error) = writer.add_interface(event.ifindex, name) {
                    self.error = Some(error.to_string());
                }
            }
            if let Err(error) = writer.write_event(&event, wall, extra) {
                self.error = Some(error.to_string());
            }
        }
        self.counts[event.stage as usize - 1] += 1;
        self.total += 1;
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    let any = capture_any(&args);
    let (config, names, selected) = build_config(&args)?;
    let expression = if args.filter.is_empty() {
        None
    } else {
        let text = args.filter.join(" ");
        Some(
            pktbaffle::compile(&text, LinkType::Ethernet, Target::Classic)
                .map_err(|error| anyhow!("invalid capture filter '{text}': {error}"))?,
        )
    };
    let cooked_expression = if any && !args.filter.is_empty() {
        let text = args.filter.join(" ");
        Some(
            pktbaffle::compile(&text, LinkType::LinuxSll, Target::Classic)
                .map_err(|error| anyhow!("invalid any-interface filter '{text}': {error}"))?,
        )
    } else {
        None
    };
    let bpf_mask = Stage::ALL[..5]
        .iter()
        .fold(0, |mask, stage| mask | stage.bit());
    let wants_bpf = config.stage_mask & bpf_mask != 0;
    let filter_value = filter::encode(if wants_bpf { expression.as_ref() } else { None })?;
    let bpf_available = fs::metadata("/sys/kernel/btf/vmlinux").is_ok();
    if wants_bpf && !bpf_available && config.stage_mask & Stage::Pcap.bit() == 0 {
        bail!("kernel BTF is required for XDP/XSK capture (/sys/kernel/btf/vmlinux)");
    }
    let offset = wall_offset_ns()?;
    let mut writer = match &args.write {
        Some(path) => Some(PcapngWriter::new(BufWriter::new(
            File::create(path).with_context(|| format!("create {}", path.display()))?,
        ))?),
        None => None,
    };
    if let Some(writer) = &mut writer {
        if any && config.stage_mask & Stage::Pcap.bit() != 0 {
            writer.add_cooked_any()?;
        }
        if !any {
            for (&index, name) in &names {
                writer.add_interface(index, name)?;
            }
        }
    }
    let state = Rc::new(RefCell::new(CaptureState {
        names,
        show_interface: any || args.interfaces.len() > 1,
        print_options: PrintOptions {
            verbose: args.verbose,
            link_header: args.link_header,
        },
        map_types: HashMap::new(),
        writer,
        offset,
        counts: [0; 6],
        total: 0,
        lost: 0,
        invalid: 0,
        limit: args.count,
        error: None,
    }));
    let mut loaded = Vec::new();
    let mut unavailable = Vec::new();
    let mut coverage = Coverage::new();
    if wants_bpf && !bpf_available {
        unavailable.push("XDP/XSK: kernel BTF unavailable".to_string());
    }
    let mut sockets = Vec::new();
    if config.stage_mask & Stage::Pcap.bit() != 0 {
        let indexes: Vec<u32> = if any {
            vec![0]
        } else {
            state.borrow().names.keys().copied().collect()
        };
        for ifindex in indexes {
            let name = if any {
                "any".to_string()
            } else {
                state.borrow().names[&ifindex].clone()
            };
            match PacketSocket::open(
                ifindex,
                args.snaplen,
                selected.pcap_in,
                selected.pcap_out,
                if any {
                    cooked_expression.as_ref()
                } else {
                    expression.as_ref()
                },
                args.sample,
            ) {
                Ok(socket) => {
                    coverage.attached(Stage::Pcap, name.clone());
                    sockets.push(socket);
                }
                Err(error) => {
                    coverage.missing(Stage::Pcap, name.clone());
                    unavailable.push(format!("{name} pcap: {error:#}"));
                }
            }
        }
    }
    if args.queue.is_some() && !sockets.is_empty() {
        eprintln!("note: --queue applies to XDP/XSK only; packet sockets do not report a queue");
    }
    let groups: [(&str, &[&str], u32); 8] = [
        (
            "redirect-native",
            &["redirect_entry", "redirect_exit"],
            Stage::Redirect.bit(),
        ),
        (
            "redirect-frame",
            &["redirect_frame_entry", "redirect_frame_exit"],
            Stage::Redirect.bit(),
        ),
        (
            "redirect-generic",
            &["redirect_generic_entry", "redirect_generic_exit"],
            Stage::Redirect.bit(),
        ),
        (
            "redirect-metadata",
            &["redirect_trace", "redirect_error_trace"],
            Stage::Redirect.bit(),
        ),
        (
            "xsk-rx-native",
            &["xsk_rx_entry", "xsk_rx_exit"],
            Stage::XskRx.bit(),
        ),
        (
            "xsk-rx-generic",
            &["xsk_generic_rx_entry", "xsk_generic_rx_exit"],
            Stage::XskRx.bit(),
        ),
        (
            "xsk-tx-generic",
            &["xsk_generic_tx_entry", "xsk_generic_tx_exit"],
            Stage::XskTx.bit(),
        ),
        (
            "xsk-tx-zero-copy",
            &[
                "xsk_tx_single_entry",
                "xsk_tx_single_exit",
                "xsk_tx_batch_entry",
                "xsk_tx_batch_exit",
            ],
            Stage::XskTx.bit(),
        ),
    ];
    let xsk_build_skb_present = if bpf_available && config.stage_mask & Stage::XskTx.bit() != 0 {
        Btf::from_vmlinux()
            .ok()
            .map(|btf| btf.type_by_name::<Func<'_>>("xsk_build_skb").is_some())
    } else {
        None
    };
    let mut redirect_data_loaded = false;
    for (label, programs, bit) in groups {
        if !bpf_available || config.stage_mask & bit == 0 {
            continue;
        }
        if label == "redirect-metadata" && !redirect_data_loaded {
            continue;
        }
        let stage = if bit == Stage::Redirect.bit() {
            Stage::Redirect
        } else if bit == Stage::XskRx.bit() {
            Stage::XskRx
        } else {
            Stage::XskTx
        };
        let result = if label == "xsk-tx-generic" && xsk_build_skb_present == Some(false) {
            Err(anyhow!("xsk_build_skb absent from kernel BTF"))
        } else {
            load_group(
                programs,
                &config,
                &filter_value,
                None,
                loaded.first().map(|item: &Loaded| &item._object),
            )
        };
        match result {
            Ok(item) => {
                coverage.attached(stage, label);
                if label.starts_with("redirect-") && label != "redirect-metadata" {
                    redirect_data_loaded = true;
                }
                loaded.push(item);
            }
            Err(error) if label == "xsk-tx-generic" => {
                let fallback = [
                    "xsk_generic_xmit_entry",
                    "xsk_generic_xmit_exit",
                    "xsk_generic_direct_xmit",
                ];
                match load_group(
                    &fallback,
                    &config,
                    &filter_value,
                    None,
                    loaded.first().map(|item: &Loaded| &item._object),
                ) {
                    Ok(item) => {
                        coverage.attached(Stage::XskTx, "generic direct-xmit fallback");
                        coverage.missing(Stage::XskTx, label);
                        eprintln!("note: xsk-tx: {error:#}; using generic direct-xmit attempts");
                        loaded.push(item);
                    }
                    Err(fallback_error) => {
                        coverage.missing(stage, label);
                        unavailable.push(format!(
                            "{label}: {error:#}; direct-xmit fallback: {fallback_error:#}"
                        ));
                    }
                }
            }
            Err(error) => {
                coverage.missing(stage, label);
                unavailable.push(format!("{label}: {error:#}"));
            }
        }
    }
    let xdp_mask = Stage::XdpIn.bit() | Stage::XdpOut.bit();
    if bpf_available && config.stage_mask & xdp_mask != 0 {
        for (&ifindex, name) in &state.borrow().names {
            match xdp_program_id(ifindex) {
                Ok(Some(main_id)) => {
                    let ids = match xdp_chain_ids(main_id) {
                        Ok(ids) => ids,
                        Err(error) => {
                            unavailable.push(format!("{name} XDP chain enumeration: {error:#}"));
                            vec![main_id]
                        }
                    };
                    if ids.len() == 1
                        && xdp_target(main_id)
                            .is_ok_and(|(_, function)| function.starts_with("xdp_dispatcher"))
                    {
                        unavailable.push(format!(
                            "{name}: XDP dispatcher has no discoverable child links"
                        ));
                    }
                    for id in ids {
                        match xdp_target(id) {
                            Ok((fd, function)) => {
                                let mut per_prog = config;
                                per_prog.prog_id = id;
                                let mut stages = Vec::new();
                                if config.stage_mask & Stage::XdpIn.bit() != 0 {
                                    stages.push("xdp_entry");
                                }
                                if config.stage_mask & Stage::XdpOut.bit() != 0 {
                                    stages.push("xdp_exit");
                                }
                                match load_group(
                                    &stages,
                                    &per_prog,
                                    &filter_value,
                                    Some((fd.as_raw_fd(), &function)),
                                    loaded.first().map(|item| &item._object),
                                ) {
                                    Ok(item) => {
                                        for stage in [Stage::XdpIn, Stage::XdpOut] {
                                            if config.stage_mask & stage.bit() != 0 {
                                                coverage.attached(stage, format!("{name}#{id}"));
                                            }
                                        }
                                        loaded.push(item);
                                    }
                                    Err(error) => {
                                        for stage in [Stage::XdpIn, Stage::XdpOut] {
                                            if config.stage_mask & stage.bit() != 0 {
                                                coverage.missing(stage, format!("{name}#{id}"));
                                            }
                                        }
                                        unavailable
                                            .push(format!("{name} XDP program {id}: {error:#}"));
                                    }
                                }
                            }
                            Err(error) => {
                                for stage in [Stage::XdpIn, Stage::XdpOut] {
                                    if config.stage_mask & stage.bit() != 0 {
                                        coverage.missing(stage, format!("{name}#{id}"));
                                    }
                                }
                                unavailable.push(format!("{name} XDP program {id}: {error:#}"))
                            }
                        }
                    }
                }
                Ok(None) => {
                    for stage in [Stage::XdpIn, Stage::XdpOut] {
                        if config.stage_mask & stage.bit() != 0 {
                            coverage.missing(stage, name.clone());
                        }
                    }
                    unavailable.push(format!("{name}: no XDP program attached"));
                }
                Err(error) => {
                    for stage in [Stage::XdpIn, Stage::XdpOut] {
                        if config.stage_mask & stage.bit() != 0 {
                            coverage.missing(stage, name.clone());
                        }
                    }
                    unavailable.push(format!("{name}: {error:#}"));
                }
            }
        }
    }
    coverage.print(config.stage_mask);
    for warning in &unavailable {
        eprintln!("unavailable: {warning}");
    }
    if loaded.is_empty() && sockets.is_empty() {
        bail!("no requested capture stage could be attached");
    }
    let buffer = if let Some(first) = loaded.first() {
        let map = first
            ._object
            .maps()
            .find(|map| map.name() == "events")
            .ok_or_else(|| anyhow!("perf map missing"))?;
        let sample_state = Rc::clone(&state);
        let lost_state = Rc::clone(&state);
        Some(
            PerfBufferBuilder::new(&map)
                .pages(args.buffer_pages)
                .sample_cb(move |_cpu, data| sample_state.borrow_mut().sample(data))
                .lost_cb(move |_cpu, count| lost_state.borrow_mut().lost += count)
                .build()?,
        )
    } else {
        None
    };
    let running = Arc::new(AtomicBool::new(true));
    let signal = Arc::clone(&running);
    ctrlc::set_handler(move || signal.store(false, Ordering::Relaxed))?;
    let started = Instant::now();
    while running.load(Ordering::Relaxed) {
        if capture_done(&state.borrow(), &args, started) {
            break;
        }
        let mut pollfds = Vec::with_capacity(sockets.len() + usize::from(buffer.is_some()));
        if let Some(buffer) = &buffer {
            pollfds.push(libc::pollfd {
                fd: buffer.epoll_fd(),
                events: libc::POLLIN,
                revents: 0,
            });
        }
        for socket in &sockets {
            pollfds.push(libc::pollfd {
                fd: socket.fd(),
                events: libc::POLLIN,
                revents: 0,
            });
        }
        let timeout_ms = args.duration.map_or(100, |limit| {
            Duration::from_secs(limit)
                .saturating_sub(started.elapsed())
                .as_millis()
                .min(100) as i32
        });
        let ready = unsafe {
            libc::poll(
                pollfds.as_mut_ptr(),
                pollfds.len() as libc::nfds_t,
                timeout_ms,
            )
        };
        if ready < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error).context("poll capture sources");
        }
        let socket_offset = usize::from(buffer.is_some());
        if let Some(buffer) = &buffer {
            if pollfds[0].revents != 0 {
                match buffer.consume() {
                    Ok(()) => {}
                    Err(error) if error.kind() == libbpf_rs::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error.into()),
                }
            }
        }
        for (index, socket) in sockets.iter_mut().enumerate() {
            if capture_done(&state.borrow(), &args, started) {
                break;
            }
            if pollfds[index + socket_offset].revents != 0 {
                socket.drain(|event| state.borrow_mut().record(event))?;
            }
        }
    }
    let mut current = state.borrow_mut();
    if let Some(writer) = &mut current.writer {
        writer.flush()?;
    }
    println!(
        "\nCapture summary: {} events, {} perf lost, {} invalid",
        current.total, current.lost, current.invalid
    );
    if !sockets.is_empty() {
        let mut drops = 0;
        for socket in &sockets {
            match socket.drops() {
                Ok(count) => drops += count,
                Err(error) => eprintln!("packet socket drop count unavailable: {error:#}"),
            }
        }
        println!("  packet socket dropped: {drops}");
    }
    let stats = kernel_stats(&loaded)?;
    println!("  stage       records   filtered    sampled   read_err   output_err   partial   batch_omitted");
    for stage in Stage::ALL {
        let index = stage as usize - 1;
        let row = if stage == Stage::Pcap {
            [
                sockets.iter().map(|s| s.filtered).sum(),
                sockets.iter().map(|s| s.read_errors).sum(),
                0,
                0,
                0,
                sockets.iter().map(|s| s.sampled).sum(),
            ]
        } else {
            stats[index]
        };
        println!(
            "  {:<9} {:>7} {:>10} {:>10} {:>10} {:>12} {:>9} {:>15}",
            stage.name(),
            current.counts[index],
            row[0],
            row[5],
            row[1],
            row[2],
            row[3],
            row[4]
        );
    }
    for warning in &unavailable {
        println!("  unavailable: {warning}");
    }
    if let Some(error) = &current.error {
        bail!("PCAPNG write failed: {error}");
    }
    Ok(())
}

fn capture_done(state: &CaptureState, args: &Args, started: Instant) -> bool {
    state.error.is_some()
        || args.count.is_some_and(|limit| state.total >= limit)
        || args
            .duration
            .is_some_and(|limit| started.elapsed() >= Duration::from_secs(limit))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, Parser};

    #[test]
    fn config_layout() {
        assert_eq!(std::mem::size_of::<Config>(), 92);
    }

    #[test]
    fn btf_function_name_is_not_truncated_to_program_name_limit() {
        let btf = Btf::from_raw("capture", BPF_OBJECT).unwrap().unwrap();
        let func = btf
            .type_by_name::<Func<'_>>("xsk_generic_xmit_entry")
            .unwrap();
        let name = btf_func_name(&btf, func.type_id().into()).unwrap();
        assert_eq!(name, "xsk_generic_xmit_entry");
        assert!(name.len() > 15);
    }

    #[test]
    fn coverage_distinguishes_partial_and_missing_paths() {
        let mut coverage = Coverage::new();
        assert_eq!(coverage.status(Stage::XskTx), "unavailable");
        coverage.attached(Stage::XskTx, "generic");
        assert_eq!(coverage.status(Stage::XskTx), "ready");
        coverage.missing(Stage::XskTx, "zero-copy");
        assert_eq!(coverage.status(Stage::XskTx), "degraded");
    }

    #[test]
    fn rejects_invalid_cli_combinations() {
        for args in [
            vec!["xpcap", "-i", "lo", "--perf-pages", "3"],
            vec!["xpcap", "-i", "lo", "--stage", "bad"],
        ] {
            let args = Args::try_parse_from(args).unwrap();
            assert!(build_config(&args).is_err());
        }
        assert!(Args::try_parse_from(["xpcap", "-c", "1"]).is_err());
        assert!(Args::try_parse_from(["xpcap", "-i", "lo", "-s", "9217"]).is_err());
        assert!(Args::try_parse_from(["xpcap", "-i", "lo", "--sample", "0"]).is_err());
        assert!(Args::try_parse_from(["xpcap", "-i", "lo", "--src", "192.0.2.1"]).is_err());
    }

    #[test]
    fn sample_period_reaches_probe_config() {
        let args = Args::try_parse_from(["xpcap", "-i", "lo", "--sample", "3"]).unwrap();
        let (config, _, _) = build_config(&args).unwrap();
        assert_eq!(config.sample, 3);
    }

    #[test]
    fn short_options_and_filter_examples_are_in_help() {
        let mut command = Args::command();
        let help = command.render_help().to_string();
        for text in [
            "-S, --stage",
            "-q, --queue",
            "-m, --sample",
            "-B, --perf-pages",
            "-v",
            "-e",
            "xpcap -i any tcp and port 443",
            "xpcap -i eth0 udp and dst port 53",
            "xpcap -i eth0 -S xsk host 192.0.2.1 and port 9000",
        ] {
            assert!(help.contains(text), "missing from help: {text}");
        }
        for example in [
            "tcp and port 443",
            "udp and dst port 53",
            "host 192.0.2.1 and port 9000",
        ] {
            pktbaffle::compile(example, LinkType::Ethernet, Target::Classic).unwrap();
        }
        let args = Args::try_parse_from([
            "xpcap", "-i", "lo", "-S", "pcap", "-q", "3", "-m", "4", "-B", "64", "tcp", "and",
            "port", "443",
        ])
        .unwrap();
        assert_eq!(args.stage.as_deref(), Some("pcap"));
        assert_eq!(args.queue, Some(3));
        assert_eq!(args.sample, 4);
        assert_eq!(args.buffer_pages, 64);
        assert_eq!(args.filter.join(" "), "tcp and port 443");
        let args = Args::try_parse_from(["xpcap", "-i", "lo", "-ev"]).unwrap();
        assert!(args.link_header && args.verbose);
    }

    #[test]
    fn selects_packet_only_or_mixed_capture() {
        let defaults = Args::try_parse_from(["xpcap", "-i", "lo"]).unwrap();
        let (config, _, selected) = build_config(&defaults).unwrap();
        assert_eq!(
            config.stage_mask,
            Stage::XskRx.bit() | Stage::XskTx.bit() | Stage::Pcap.bit()
        );
        assert!(selected.pcap_in && selected.pcap_out);

        let packet_only = Args::try_parse_from(["xpcap", "-i", "lo", "--stage", "pcap"]).unwrap();
        let (config, _, selected) = build_config(&packet_only).unwrap();
        assert_eq!(config.stage_mask, Stage::Pcap.bit());
        assert!(selected.pcap_in && selected.pcap_out);

        let mixed =
            Args::try_parse_from(["xpcap", "-i", "lo", "--stage", "pcap,xsk-rx,xsk-tx"]).unwrap();
        let (config, _, _) = build_config(&mixed).unwrap();
        assert_eq!(
            config.stage_mask,
            Stage::Pcap.bit() | Stage::XskRx.bit() | Stage::XskTx.bit()
        );
    }

    #[test]
    fn tcpdump_direction_and_source_aliases() {
        let args = Args::try_parse_from([
            "xpcap", "-i", "lo", "--stage", "xsk,pcap", "-Q", "in", "tcp", "and", "port", "443",
        ])
        .unwrap();
        assert_eq!(args.filter.join(" "), "tcp and port 443");
        let (config, _, selected) = build_config(&args).unwrap();
        assert_eq!(config.stage_mask, Stage::XskRx.bit() | Stage::Pcap.bit());
        assert!(selected.pcap_in && !selected.pcap_out);

        let args = Args::try_parse_from([
            "xpcap",
            "-i",
            "lo",
            "--stage",
            "xsk-in,pcap-out",
            "-Q",
            "inout",
        ])
        .unwrap();
        let (config, _, selected) = build_config(&args).unwrap();
        assert_eq!(config.stage_mask, Stage::XskRx.bit() | Stage::Pcap.bit());
        assert!(!selected.pcap_in && selected.pcap_out);

        let args =
            Args::try_parse_from(["xpcap", "-i", "lo", "--stage", "xsk-in", "-Q", "out"]).unwrap();
        assert!(build_config(&args).is_err());
    }

    #[test]
    fn capture_lines_show_interface_only_for_multiple_interfaces() {
        let mut names = HashMap::from([(1, "eth0".to_string())]);
        let packet = [0u8; 14];
        let mut event = Event::packet(1, 0, false, packet.len() as u32, &packet);
        let single = format_capture_line(&names, false, PrintOptions::default(), &event, 0, "");
        assert!(!single.contains("eth0"));
        assert!(single.contains("q-   PCAP     IN"));
        assert!(single.contains("length 14"));
        let truncated = Event::packet(1, 0, false, 100, &packet);
        let line = format_capture_line(&names, false, PrintOptions::default(), &truncated, 0, "");
        assert!(line.contains("frame length 100 (captured 14)"));
        assert!(!line.contains("partial"));

        names.insert(2, "eth1".to_string());
        let multiple = format_capture_line(&names, true, PrintOptions::default(), &event, 0, "");
        assert!(multiple.contains("eth0         q-   PCAP     IN"));

        event.stage = Stage::XskRx;
        event.queue = 3;
        event.ifindex = 2;
        let xsk = format_capture_line(&names, true, PrintOptions::default(), &event, 0, "");
        assert!(xsk.contains("eth1         q3   XSK      IN"));
    }

    #[test]
    fn any_is_wildcard_and_cannot_be_combined() {
        let args = Args::try_parse_from(["xpcap", "-i", "any"]).unwrap();
        let (config, names, _) = build_config(&args).unwrap();
        assert_eq!(config.ifcount, 0);
        assert!(!names.is_empty());
        let mixed = Args::try_parse_from(["xpcap", "-i", "any", "-i", "lo"]).unwrap();
        assert!(build_config(&mixed).is_err());
    }
}
