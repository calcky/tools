#[cfg(not(target_os = "linux"))]
compile_error!("ctop requires Linux conntrack");
mod engine;
mod model;
mod netlink;
mod offline;
mod options;
mod ui;

use std::{
    io::{self, BufReader, IsTerminal, Write},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

fn run() -> Result<(), String> {
    let mut o = match options::parse(std::env::args().skip(1))? {
        options::Command::Help => {
            print!("{}", options::HELP);
            return Ok(());
        }
        options::Command::Version => {
            println!("ctop {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        options::Command::Run(o) => o,
    };
    o.batch |= !io::stdout().is_terminal()
        || (o.input.is_none() && !io::stdin().is_terminal())
        || std::env::var("TERM").as_deref() == Ok("dumb");
    let mut engine = if let Some(source) = &o.input {
        if source == "-" {
            if io::stdin().is_terminal() {
                return Err("-f requires a file or piped input; try conntrack -L | ctop -f".into());
            }
            offline::load(io::stdin().lock(), "stdin".into())?
        } else {
            let file = std::fs::File::open(source).map_err(|e| format!("{source}: {e}"))?;
            offline::load(BufReader::new(file), source.clone())?
        }
    } else {
        engine::Engine::open(o.refresh).map_err(diagnostic)?
    };
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    ctrlc::set_handler(move || flag.store(true, Ordering::Relaxed)).map_err(|e| e.to_string())?;
    if o.input.is_some() {
        return run_offline(&o, &mut engine, &stop);
    }
    let mut screen = if o.batch {
        None
    } else {
        Some(ui::Screen::open().map_err(diagnostic)?)
    };
    let mut view = ui::View::new(&o);
    let start = Instant::now();
    let mut last = start;
    let mut draw = start;
    let mut count = 0;
    while !stop.load(Ordering::Relaxed) {
        engine.pump().map_err(diagnostic)?;
        if engine.stale {
            view.rates_valid = false;
        }
        if screen.is_some() && view.keys(&engine, &o).map_err(diagnostic)? {
            break;
        }
        let now = Instant::now();
        if engine.ready && now.duration_since(last) >= o.interval {
            view.update(&mut engine, &o, now.duration_since(last).as_secs_f64());
            last = now;
            if o.batch {
                view.batch(&engine, &o, &mut io::stdout().lock())
                    .map_err(diagnostic)?;
                io::stdout().flush().map_err(diagnostic)?;
                count += 1;
                if o.count.is_some_and(|n| count >= n) {
                    break;
                }
            }
        }
        if let Some(screen) = &mut screen {
            if now >= draw {
                screen
                    .terminal
                    .draw(|f| view.draw(f, &engine, &o))
                    .map_err(diagnostic)?;
                draw = now + Duration::from_millis(250);
            }
        }
        if !engine.ready && start.elapsed() > Duration::from_secs(35) {
            return Err(format!(
                "initial conntrack snapshot unavailable: {}",
                engine.message
            ));
        }
        let wait = if engine.ready {
            o.interval
                .saturating_sub(last.elapsed())
                .min(Duration::from_millis(100))
        } else {
            Duration::from_millis(100)
        };
        let mut fds = [
            libc::pollfd {
                fd: engine.fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: if screen.is_some() {
                    libc::STDIN_FILENO
                } else {
                    -1
                },
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let result = unsafe {
            libc::poll(
                fds.as_mut_ptr(),
                fds.len() as _,
                wait.as_millis().max(1) as i32,
            )
        };
        if result < 0 {
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(diagnostic(err));
            }
        }
    }
    Ok(())
}
fn run_offline(
    o: &options::Options,
    engine: &mut engine::Engine,
    stop: &AtomicBool,
) -> Result<(), String> {
    let mut view = ui::View::new(o);
    view.update(engine, o, 1.0);
    // Crossterm uses /dev/tty for keys when stdin supplied the snapshot.
    let terminal_input = io::stdin().is_terminal()
        || std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .is_ok();
    if o.batch || !terminal_input {
        return view
            .batch(engine, o, &mut io::stdout().lock())
            .map_err(|e| e.to_string());
    }
    let mut screen = ui::Screen::open().map_err(|e| e.to_string())?;
    screen
        .terminal
        .draw(|f| view.draw(f, engine, o))
        .map_err(|e| e.to_string())?;
    while !stop.load(Ordering::Relaxed) {
        if crossterm::event::poll(Duration::from_millis(250)).map_err(|e| e.to_string())? {
            if view.keys(engine, o).map_err(|e| e.to_string())? {
                break;
            }
            screen
                .terminal
                .draw(|f| view.draw(f, engine, o))
                .map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}
fn diagnostic(e: io::Error) -> String {
    if matches!(e.raw_os_error(), Some(libc::EPERM | libc::EACCES)) {
        format!(
            "{e}; run with CAP_NET_ADMIN in the target network namespace (for example sudo ctop)"
        )
    } else {
        e.to_string()
    }
}
fn main() {
    if let Err(error) = run() {
        if !error.contains("Broken pipe") {
            eprintln!("ctop: {error}");
            std::process::exit(1);
        }
    }
}
