mod analyze;
mod buffers;
mod client;
mod datagram;
mod expiry;
mod net;
mod options;
mod pending;
mod ports;
mod record;
mod schedule;
mod server;
mod slots;
mod stats;
mod tuning;
mod wire;

use std::{
    fs, io,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

fn run() -> io::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|arg| arg == "-h") {
        println!("{}", options::HELP);
        return Ok(());
    }
    if args.iter().any(|arg| arg == "-v") {
        println!("flowgen {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    let o = options::parse(args).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    tuning::validate(&o)?;
    if let Some(dir) = &o.analyze {
        let has_events = fs::read_dir(dir)?.flatten().any(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "fgr")
        });
        if !has_events {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "offline analysis requires event recordings from -L events",
            ));
        }
        return analyze::run(dir);
    }
    let stop = Arc::new(AtomicBool::new(false));
    let signal = stop.clone();
    ctrlc::set_handler(move || {
        signal.store(true, Ordering::Relaxed);
    })
    .map_err(io::Error::other)?;
    if o.server {
        server::run(&o, stop)
    } else {
        client::run(&o, stop)
    }
}
fn main() {
    if let Err(e) = run() {
        if e.kind() == io::ErrorKind::BrokenPipe {
            return;
        }
        eprintln!("flowgen: {e}");
        std::process::exit(1);
    }
}
