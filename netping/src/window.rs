use crate::{
    client,
    net::{self, Reactor},
    options::{Mode, Options},
    output::Printer,
    probe::{Link, Probe, Tokens},
    terminal::{Action, Terminal},
    ui,
};
use mio::Events;
use std::{
    io,
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

const REFRESH: Duration = Duration::from_millis(250);

fn probes(o: &Options, ip: IpAddr, start: Instant, r: &Reactor, tokens: &mut Tokens) -> Vec<Probe> {
    [
        Mode::Icmp,
        Mode::Udp,
        if o.mode == Mode::Connect {
            Mode::Connect
        } else {
            Mode::Tcp
        },
    ]
    .into_iter()
    .map(|mode| {
        let mut options = o.clone();
        options.mode = mode;
        options.port = match mode {
            Mode::Icmp => 0,
            Mode::Udp => o.port,
            _ => o.tcp_port.unwrap_or(o.port),
        };
        let addr = SocketAddr::new(ip, options.port);
        Probe::new(options.clone(), addr, start, true, r, tokens)
            .unwrap_or_else(|e| Probe::unavailable(options, addr, start, e.to_string()))
    })
    .collect()
}

fn row(p: &Probe) -> ui::Row {
    let w = &p.tracker.total;
    let tcp = matches!(p.options.mode, Mode::Tcp | Mode::Connect);
    let alert = if tcp {
        match p.link {
            Link::Retry(_) => Some(ui::Alert::Disconnected),
            Link::Connecting(_) if p.ever_ready || p.connect_failed > 0 => {
                Some(ui::Alert::Disconnected)
            }
            Link::Closed if p.error.is_some() => Some(ui::Alert::Disconnected),
            Link::Ready => match p.last_failure {
                Some("timeout") => Some(ui::Alert::Timeout),
                Some(_) => Some(ui::Alert::Failed),
                None if p.retrans.active() => Some(ui::Alert::Retrans),
                None => None,
            },
            _ => None,
        }
    } else {
        None
    };
    ui::Row {
        name: p.options.mode.name().into(),
        sent: w.sent,
        received: w.recv,
        loss: w.loss(),
        last: p.last_failure.map(str::to_owned).unwrap_or_else(|| {
            p.last.map_or_else(
                || "-".into(),
                |d| format!("{:.3}", d.as_secs_f64() * 1000.0),
            )
        }),
        min: (w.recv > 0).then_some(w.min),
        avg: (w.recv > 0).then_some(w.mean),
        max: (w.recv > 0).then_some(w.max),
        mdev: (w.recv > 0).then(|| w.deviation()),
        p50: (w.recv > 0).then(|| w.quantile(0.5)),
        p95: (w.recv > 0).then(|| w.quantile(0.95)),
        p99: (w.recv > 0).then(|| w.quantile(0.99)),
        pending: p.tracker.pending.len(),
        timeout: w.timeout,
        failed: w.failed,
        reordered: w.reordered,
        duplicate: w.duplicate,
        late: w.late,
        invalid: w.invalid,
        limited: w.limited,
        skipped: w.skipped,
        connect_failed: p.connect_failed,
        retrans: tcp.then(|| p.retrans.view()),
        alert,
        state: match (p.link, p.last_failure) {
            (Link::Ready, Some("timeout")) => "Timeout",
            (Link::Ready, Some(_)) => "Failed",
            _ => p.state(),
        }
        .into(),
        error: p.error.clone(),
        bad: p.last_failure.is_some()
            || matches!(p.link, Link::Retry(_) | Link::Unavailable)
            || alert.is_some_and(|a| a != ui::Alert::Retrans),
    }
}
fn view(o: &Options, ip: IpAddr, start: Instant, paused: bool, probes: &[Probe]) -> ui::View {
    let now = Instant::now();
    ui::View {
        host: o.host.clone().unwrap(),
        ip,
        udp_port: o.port,
        tcp_port: o.tcp_port.unwrap_or(o.port),
        interval: o.interval,
        timeout: o.timeout,
        elapsed: now - start,
        paused,
        draining: probes.iter().all(|p| !p.sending(now)),
        rows: probes.iter().map(row).collect(),
    }
}

pub fn run(o: &Options, r: &mut Reactor) -> Result<bool, Box<dyn std::error::Error>> {
    let ip = net::resolve(o.host.as_ref().unwrap(), o.v6, o.port)?.ip();
    let mut terminal = Terminal::enter()?;
    let mut state = ui::State::default();
    let mut tokens = Tokens::default();
    let mut start = Instant::now();
    let mut probes = probes(o, ip, start, r, &mut tokens);
    let mut paused = false;
    let mut next_draw = start;
    let mut events = Events::with_capacity(1024);
    'running: loop {
        if r.stopped() {
            break;
        }
        for _ in 0..64 {
            match terminal.key()? {
                Some(Action::Quit) => break 'running,
                Some(Action::Up) => state.selected = (state.selected + 2) % 3,
                Some(Action::Down) => state.selected = (state.selected + 1) % 3,
                Some(Action::Pause) => {
                    paused = !paused;
                    if !paused {
                        for p in &mut probes {
                            p.resume(Instant::now());
                        }
                    }
                }
                Some(Action::Reset) => {
                    probes.clear();
                    start = Instant::now();
                    paused = false;
                    probes = self::probes(o, ip, start, r, &mut tokens);
                }
                None => break,
            }
        }
        let now = Instant::now();
        for p in &mut probes {
            if let Err(e) = p.tick(now, paused, r, &mut tokens, &mut ()) {
                p.disable(e.to_string());
            }
        }
        if now >= next_draw {
            terminal.draw(&view(o, ip, start, paused, &probes), &mut state)?;
            next_draw = Instant::now() + REFRESH;
        }
        if probes.iter().all(|p| p.done(Instant::now())) {
            break;
        }
        let now = Instant::now();
        let wake = probes
            .iter()
            .fold(next_draw, |at, p| at.min(p.deadline(now, paused)));
        client::poll(r, &mut events, wake)?;
        for event in &events {
            if let Some(p) = probes.iter_mut().find(|p| p.owns(event.token())) {
                if let Err(e) = p.on_io(event, r, &mut ()) {
                    p.disable(e.to_string());
                }
            }
        }
    }
    drop(terminal);
    let elapsed = start.elapsed();
    for p in &mut probes {
        p.finish_tcp();
        let mut printer = Printer::new(io::stdout().lock(), &p.options, p.addr)?;
        printer.summary(&p.tracker, elapsed)?;
        printer.retrans(p.retrans.summary())?;
        if p.connect_failed > 0 {
            println!("  TCP connection setup failures: {}", p.connect_failed);
        }
        if let Some(error) = &p.error {
            println!("  {} | last error: {error}", p.state());
        }
    }
    Ok(probes
        .iter()
        .all(|p| p.tracker.total.recv > 0 && p.link != Link::Unavailable))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stats::Event;
    #[test]
    fn snapshots_keep_missing_latency_and_pending_separate() {
        let o = crate::options::parse(["-w", "host"].map(str::to_owned)).unwrap();
        let now = Instant::now();
        let mut p = Probe::unavailable(
            o,
            "127.0.0.1:0".parse().unwrap(),
            now,
            "permission denied".into(),
        );
        p.tracker.sent(1, now);
        let v = row(&p);
        assert_eq!(v.pending, 1);
        assert_eq!(v.loss, 0.0);
        assert_eq!(v.min, None);
        assert!(v.bad);
        p.tracker.record(Event::Received(Duration::from_millis(2)));
        p.last = Some(Duration::from_millis(2));
        p.last_failure = Some("timeout");
        let v = row(&p);
        assert_eq!(v.avg, Some(2.0));
        assert_eq!(v.last, "timeout");
        assert_eq!(v.error.as_deref(), Some("permission denied"));
    }

    #[test]
    fn tcp_alert_priority_and_recovery_preserve_cumulative_counters() {
        let o = crate::options::parse(["-t", "host"].map(str::to_owned)).unwrap();
        let now = Instant::now();
        let mut p = Probe::unavailable(
            o,
            "127.0.0.1:11111".parse().unwrap(),
            now,
            "old error".into(),
        );
        p.link = Link::Connecting(now);
        assert_eq!(row(&p).alert, None);
        p.connect_failed = 1;
        assert_eq!(row(&p).alert, Some(ui::Alert::Disconnected));
        p.link = Link::Ready;
        p.tracker.record(Event::Received(Duration::from_millis(2)));
        p.retrans.tx.observe(Some(3));
        assert_eq!(row(&p).alert, Some(ui::Alert::Retrans));
        assert!(!row(&p).bad);
        assert_eq!(row(&p).loss, 0.0);
        p.last_failure = Some("timeout");
        assert_eq!(row(&p).alert, Some(ui::Alert::Timeout));
        assert!(row(&p).bad);
        p.link = Link::Retry(now);
        assert_eq!(row(&p).alert, Some(ui::Alert::Disconnected));
        p.link = Link::Connecting(now);
        assert_eq!(row(&p).alert, Some(ui::Alert::Disconnected));
        p.link = Link::Ready;
        p.last_failure = Some("failed");
        assert_eq!(row(&p).alert, Some(ui::Alert::Failed));
        p.last_failure = None;
        assert_eq!(row(&p).alert, Some(ui::Alert::Retrans));
        p.retrans.sample(now + Duration::from_secs(1));
        p.retrans.sample(now + Duration::from_secs(2));
        assert_eq!(row(&p).alert, None);
        assert!(!row(&p).bad);
        assert_eq!(row(&p).retrans.unwrap().tx.total, Some(3));
        assert_eq!(row(&p).error.as_deref(), Some("old error"));
        p.options.mode = Mode::Connect;
        p.retrans.tx.completed(Some(1));
        assert_eq!(row(&p).alert, Some(ui::Alert::Retrans));
        p.last_failure = Some("timeout");
        assert_eq!(row(&p).alert, Some(ui::Alert::Timeout));
        p.options.mode = Mode::Udp;
        assert_eq!(row(&p).alert, None);
        assert!(row(&p).retrans.is_none());
    }
}
