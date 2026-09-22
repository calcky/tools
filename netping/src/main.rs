mod client;
mod icmp;
mod mss;
mod mss_capture;
mod mtu;
mod mtu_socket;
mod net;
mod options;
mod output;
mod probe;
mod server;
mod stats;
mod tcp;
mod terminal;
mod ui;
mod window;
mod wire;

use std::{io, process::ExitCode};
fn run() -> Result<bool, Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args == ["-h"] {
        print!("{}", options::HELP);
        return Ok(true);
    }
    if args == ["-v"] {
        println!("netping {}", env!("CARGO_PKG_VERSION"));
        return Ok(true);
    }
    let o = options::parse(args).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    if o.window {
        terminal::validate()?;
    }
    let mut reactor = net::Reactor::new()?;
    if o.server {
        server::run(&o, &mut reactor)?;
        Ok(true)
    } else if o.window {
        window::run(&o, &mut reactor)
    } else if o.mss {
        mss::run(&o, &mut reactor)
    } else if o.mtu {
        mtu::run(&o, &mut reactor)
    } else {
        client::run(&o, &mut reactor)
    }
}
fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            if e.downcast_ref::<io::Error>()
                .is_some_and(|e| e.kind() == io::ErrorKind::BrokenPipe)
            {
                return ExitCode::SUCCESS;
            }
            eprintln!("netping: {e}");
            ExitCode::from(2)
        }
    }
}
