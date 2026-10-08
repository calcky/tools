use crate::{
    options::Options,
    output::Printer,
    probe::{Link, Probe},
    stats::Window,
    tcp,
};
use std::{
    io::{self, Write},
    time::Duration,
};

pub struct Summary {
    pub total: Window,
    pub current: Window,
    pub pending: usize,
    pub retrans: tcp::View,
}

pub fn summarize<'a>(probes: impl IntoIterator<Item = &'a Probe>, final_sample: bool) -> Summary {
    let mut summary = Summary {
        total: Window::default(),
        current: Window::default(),
        pending: 0,
        retrans: tcp::View {
            tx: tcp::CounterView {
                total: Some(0),
                rate: Some(0.0),
            },
            rx: tcp::CounterView {
                total: Some(0),
                rate: Some(0.0),
            },
        },
    };
    for p in probes {
        summary.total.merge(&p.tracker.total);
        summary.current.merge(&p.tracker.current);
        summary.pending += p.tracker.pending.len();
        let retrans = if final_sample {
            p.retrans.summary()
        } else {
            p.retrans.view()
        };
        for (sum, counter) in [
            (&mut summary.retrans.tx, retrans.tx),
            (&mut summary.retrans.rx, retrans.rx),
        ] {
            sum.total = sum.total.zip(counter.total).map(|(a, b)| a + b);
            sum.rate = sum.rate.zip(counter.rate).map(|(a, b)| a + b);
        }
    }
    summary
}

pub fn successful(probes: &[Probe]) -> bool {
    probes
        .iter()
        .all(|p| p.tracker.total.recv > 0 && !p.fatal && p.link != Link::Unavailable)
}

pub fn print_summary(o: &Options, probes: &mut [Probe], elapsed: Duration) -> io::Result<()> {
    let mut printer = Printer::new(io::stdout().lock(), o, probes[0].addr)?;
    write_summary(&mut printer, probes, elapsed)
}

pub fn write_summary<W: Write>(
    printer: &mut Printer<W>,
    probes: &mut [Probe],
    elapsed: Duration,
) -> io::Result<()> {
    for p in probes.iter_mut() {
        p.finish_tcp();
    }
    let summary = summarize(probes.iter(), true);
    printer.summary_window(&summary.total, summary.pending, elapsed)?;
    printer.retrans(summary.retrans)?;
    printer.sessions_header()?;
    for (index, p) in probes.iter().enumerate() {
        printer.session_row(index + 1, &p.local_label(), &p.tracker, p.state())?;
    }
    for (index, p) in probes.iter().enumerate() {
        printer.session_error(index + 1, p.connect_failed, p.error.as_deref())?;
    }
    Ok(())
}

pub fn clear_current(probes: &mut [Probe]) {
    for p in probes {
        p.tracker.current = Window::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stats::Event;
    use std::time::Instant;

    #[test]
    fn aggregation_keeps_sessions_sequence_spaces_and_pending_separate() {
        let options = crate::options::parse(["-u", "-j", "2", "host"].map(str::to_owned)).unwrap();
        let now = Instant::now();
        let mut probes: Vec<_> = (0..2)
            .map(|_| {
                Probe::unavailable(
                    options.clone(),
                    "127.0.0.1:11111".parse().unwrap(),
                    now,
                    "test".into(),
                )
            })
            .collect();
        for p in &mut probes {
            p.tracker.sent(1, now);
        }
        probes[0].tracker.receive(1, now + Duration::from_millis(5));
        let summary = summarize(probes.iter(), false);
        assert_eq!(
            (summary.total.sent, summary.total.recv, summary.pending),
            (2, 1, 1)
        );
        assert_eq!(summary.total.loss(), 0.0);
        probes[1].tracker.expire(now + options.timeout);
        probes[1].tracker.record(Event::Skipped(2));
        let summary = summarize(probes.iter(), false);
        assert_eq!(
            (
                summary.total.timeout,
                summary.total.skipped,
                summary.pending
            ),
            (1, 2, 0)
        );
        assert_eq!(summary.total.loss(), 50.0);
        clear_current(&mut probes);
        assert_eq!(summarize(probes.iter(), false).current.sent, 0);
        assert_eq!(summarize(probes.iter(), false).total.sent, 2);
    }
}
