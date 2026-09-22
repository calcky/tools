use crate::{
    net::{self, Reactor},
    options::{Mode, Options},
    output::Printer,
    probe::{Link, Probe, Reporter, Tokens},
    stats::Outcome,
};
use mio::Events;
use std::{
    io::{self, Write},
    time::{Duration, Instant},
};

impl<W: Write> Reporter for Printer<W> {
    fn result(&mut self, seq: u64, result: &Outcome) -> io::Result<()> {
        self.result(seq, result)
    }
    fn failure(&mut self, seq: u64, message: &str) -> io::Result<()> {
        self.failure(seq, message)
    }
    fn error(&mut self, message: &str) -> io::Result<()> {
        eprintln!("netping: {message}");
        Ok(())
    }
}

pub fn run(o: &Options, r: &mut Reactor) -> Result<bool, Box<dyn std::error::Error>> {
    let addr = net::resolve(
        o.host.as_ref().unwrap(),
        o.v6,
        if o.mode == Mode::Icmp { 0 } else { o.port },
    )?;
    let mut tokens = Tokens::default();
    let mut setup = o.clone();
    setup.duration = None;
    let mut p = Probe::new(setup, addr, Instant::now(), false, r, &mut tokens)?;
    let mut events = Events::with_capacity(512);
    while !p.ever_ready && !p.fatal && !r.stopped() {
        p.tick(Instant::now(), true, r, &mut tokens, &mut ())?;
        if p.fatal {
            break;
        }
        poll(r, &mut events, p.deadline(Instant::now(), true))?;
        for event in &events {
            p.on_io(event, r, &mut ())?;
        }
    }
    if p.fatal && !p.ever_ready {
        return Err(io::Error::other(p.error.unwrap_or_else(|| "TCP setup failed".into())).into());
    }
    if r.stopped() {
        return Ok(false);
    }
    let start = Instant::now();
    p.options = o.clone();
    p.restart_clock(start);
    let mut printer = Printer::new(io::stdout().lock(), o, addr)?;
    let mut last_report = start;
    while !r.stopped() {
        let now = Instant::now();
        p.tick(now, false, r, &mut tokens, &mut printer)?;
        if p.done(Instant::now()) {
            break;
        }
        if o.bench && now.duration_since(last_report) >= Duration::from_secs(1) {
            printer.sample(&mut p.tracker, now - start, now - last_report)?;
            last_report = now;
        }
        let mut wake = p.deadline(Instant::now(), false);
        if o.bench {
            wake = wake.min(last_report + Duration::from_secs(1));
        }
        poll(r, &mut events, wake)?;
        for event in &events {
            p.on_io(event, r, &mut printer)?;
        }
    }
    let now = Instant::now();
    if o.bench && now > last_report {
        printer.sample(&mut p.tracker, now - start, now - last_report)?;
    }
    p.finish_tcp();
    printer.summary(&p.tracker, now - start)?;
    printer.retrans(p.retrans.summary())?;
    Ok(p.tracker.total.recv > 0 && !p.fatal && p.link != Link::Unavailable)
}

pub fn poll(r: &mut Reactor, events: &mut Events, wake: Instant) -> io::Result<()> {
    match r
        .poll
        .poll(events, Some(wake.saturating_duration_since(Instant::now())))
    {
        Err(e) if e.kind() == io::ErrorKind::Interrupted => {
            events.clear();
            Ok(())
        }
        result => result,
    }
}
