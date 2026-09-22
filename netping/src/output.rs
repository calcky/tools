use crate::{
    options::{Mode, Options},
    stats::{Outcome, Tracker, Window},
};
use std::{
    io::{self, Write},
    net::SocketAddr,
    time::Duration,
};
pub struct Printer<W: Write> {
    out: W,
    bench: bool,
    mode: Mode,
    lines: usize,
}
impl<W: Write> Printer<W> {
    pub fn new(mut out: W, o: &Options, addr: SocketAddr) -> io::Result<Self> {
        writeln!(
            out,
            "netping | {} | {} | {} | {}",
            o.mode.name(),
            if o.mode == Mode::Icmp {
                addr.ip().to_string()
            } else {
                addr.to_string()
            },
            if o.mode == Mode::Connect {
                "connection time".into()
            } else {
                format!("{} bytes", o.size)
            },
            if o.bench { "performance" } else { "ping" }
        )?;
        out.flush()?;
        Ok(Self {
            out,
            bench: o.bench,
            mode: o.mode,
            lines: 0,
        })
    }
    pub fn result(&mut self, seq: u64, r: &Outcome) -> io::Result<()> {
        if self.bench {
            return Ok(());
        }
        let name = if self.mode == Mode::Connect {
            "connect"
        } else {
            "rtt"
        };
        match r {
            Outcome::Received(d) | Outcome::Reordered(d) => writeln!(
                self.out,
                "seq={seq} {name}={:.6} ms{}",
                d.as_secs_f64() * 1000.0,
                if matches!(r, Outcome::Reordered(_)) {
                    " reordered"
                } else {
                    ""
                }
            )?,
            Outcome::Late => writeln!(self.out, "seq={seq} late")?,
            Outcome::Duplicate => writeln!(self.out, "seq={seq} duplicate")?,
            Outcome::Invalid => return Ok(()),
        };
        self.out.flush()
    }
    pub fn failure(&mut self, seq: u64, message: &str) -> io::Result<()> {
        if !self.bench {
            writeln!(self.out, "seq={seq} {message}")?;
            self.out.flush()?;
        }
        Ok(())
    }
    pub fn sample(&mut self, s: &mut Tracker, elapsed: Duration, span: Duration) -> io::Result<()> {
        if !self.bench {
            return Ok(());
        }
        if self.lines.is_multiple_of(20) {
            writeln!(self.out," ELAPSED      TX/s      RX/s   TX-kB/s   RX-kB/s   PEND   TIMEOUT  FAILED {}   MIN(ms)   AVG(ms)   P99(ms)   MAX(ms) LIMITED SKIPPED",if self.mode.datagram(){" LOSS%"}else{" FAIL%"})?;
        }
        let w = &s.current;
        let secs = span.as_secs_f64().max(1e-9);
        let bandwidth = if self.mode == Mode::Connect {
            format!("{:>9} {:>9}", "-", "-")
        } else {
            format!(
                "{:9.2} {:9.2}",
                w.tx_bytes as f64 / secs / 1000.0,
                w.rx_bytes as f64 / secs / 1000.0
            )
        };
        let values = if w.recv == 0 {
            "        -         -         -         -".into()
        } else {
            format!(
                "{:9.3} {:9.3} {:9.3} {:9.3}",
                w.min,
                w.mean,
                w.quantile(0.99),
                w.max
            )
        };
        writeln!(
            self.out,
            "{:8.3}s {:9.2} {:9.2} {} {:6} {:9} {:7} {:6.2} {} {:7} {:7}",
            elapsed.as_secs_f64(),
            w.sent as f64 / secs,
            w.recv as f64 / secs,
            bandwidth,
            s.pending.len(),
            w.timeout,
            w.failed,
            s.total.loss(),
            values,
            w.limited,
            w.skipped
        )?;
        self.lines += 1;
        s.current = Window::default();
        self.out.flush()
    }
    pub fn summary(&mut self, s: &Tracker, elapsed: Duration) -> io::Result<()> {
        let w = &s.total;
        writeln!(
            self.out,
            "\n--- {} statistics | {:.3} s ---\n",
            self.mode.name(),
            elapsed.as_secs_f64()
        )?;
        let fields = [
            ("Sent", w.sent.to_string()),
            ("Received", w.recv.to_string()),
            (
                if self.mode.datagram() {
                    "Loss"
                } else {
                    "Failure"
                },
                format!("{:.2}%", w.loss()),
            ),
            ("Timeout", w.timeout.to_string()),
            ("Failed", w.failed.to_string()),
            ("Pending", s.pending.len().to_string()),
            ("Reordered", w.reordered.to_string()),
            ("Duplicate", w.duplicate.to_string()),
            ("Late", w.late.to_string()),
            ("Invalid", w.invalid.to_string()),
            ("Limited", w.limited.to_string()),
            ("Skipped", w.skipped.to_string()),
        ];
        let width = fields
            .iter()
            .map(|(_, v)| v.len())
            .max()
            .unwrap_or(0)
            .max(9);
        let columns = if 2 + 3 * (10 + width) + 6 <= 80 { 3 } else { 2 };
        for row in fields.chunks(columns) {
            let cells: Vec<_> = row
                .iter()
                .map(|(label, value)| format!("{label:<9} {value:>width$}"))
                .collect();
            writeln!(self.out, "  {}", cells.join("   "))?;
        }
        writeln!(self.out)?;
        if self.mode != Mode::Connect {
            let secs = elapsed.as_secs_f64().max(1e-9);
            let tx_kb = w.tx_bytes as f64 / secs / 1000.0;
            let rx_kb = w.rx_bytes as f64 / secs / 1000.0;
            let tx_mbit = tx_kb * 8.0 / 1000.0;
            let rx_mbit = rx_kb * 8.0 / 1000.0;
            writeln!(
                self.out,
                "  Payload TX/RX = {}/{} bytes",
                w.tx_bytes, w.rx_bytes
            )?;
            writeln!(
                self.out,
                "  Avg bandwidth TX/RX = {:.2}/{:.2} kB/s ({:.3}/{:.3} Mbit/s)",
                tx_kb, rx_kb, tx_mbit, rx_mbit
            )?;
            writeln!(self.out)?;
        }
        self.latencies(
            if self.mode == Mode::Connect {
                "connect"
            } else {
                "rtt"
            },
            &["min", "avg", "max", "mdev"],
            &[w.min, w.mean, w.max, w.deviation()],
            w.recv > 0,
            6,
        )?;
        self.latencies(
            "Percentiles",
            &["P50", "P95", "P99"],
            &[w.quantile(0.5), w.quantile(0.95), w.quantile(0.99)],
            w.recv > 0,
            3,
        )?;
        self.out.flush()
    }

    pub fn retrans(&mut self, view: crate::tcp::View) -> io::Result<()> {
        if matches!(self.mode, Mode::Tcp | Mode::Connect) {
            let value = |v: Option<u64>| v.map_or_else(|| "-".into(), |v| v.to_string());
            writeln!(
                self.out,
                "  TCP retrans Tx/Rx = {}/{} segments",
                value(view.tx.total),
                value(view.rx.total)
            )?;
            self.out.flush()?;
        }
        Ok(())
    }

    fn latencies(
        &mut self,
        label: &str,
        names: &[&str],
        values: &[f64],
        present: bool,
        precision: usize,
    ) -> io::Result<()> {
        let fields: Vec<_> = values
            .iter()
            .map(|value| {
                if present {
                    format!("{value:.precision$}")
                } else {
                    "-".into()
                }
            })
            .collect();
        writeln!(
            self.out,
            "  {label} {} = {} ms",
            names.join("/"),
            fields.join("/")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{options, stats::Event};
    use std::time::Instant;

    fn summary(mode: Mode, tracker: &Tracker) -> String {
        let mut o = options::parse(["localhost".to_owned()]).unwrap();
        o.mode = mode;
        let mut out = Vec::new();
        let mut p = Printer::new(&mut out, &o, "127.0.0.1:11111".parse().unwrap()).unwrap();
        p.summary(tracker, Duration::from_secs(2)).unwrap();
        String::from_utf8(out).unwrap()
    }
    #[test]
    fn summary_keeps_pending_separate_and_shows_missing_latency() {
        let mut s = Tracker::new(Duration::from_secs(1));
        s.sent(1, Instant::now());
        let out = summary(Mode::Udp, &s);
        assert!(out
            .lines()
            .any(|line| line.split_whitespace().collect::<Vec<_>>()
                == ["Timeout", "0", "Failed", "0", "Pending", "1"]));
        assert!(out.contains("Loss") && out.contains("0.00%"));
        assert!(out.contains("Payload TX/RX = 0/0 bytes"));
        assert!(!out.contains("inf") && !out.contains("NaN") && !out.contains('\x1b'));
        assert!(out.contains("  rtt min/avg/max/mdev = -/-/-/- ms\n"));
        assert!(out.contains("  Percentiles P50/P95/P99 = -/-/- ms\n"));
        let out = summary(Mode::Connect, &s);
        assert!(out.contains("Failure") && out.contains("connect min/avg/max/mdev"));
        assert!(!out.contains("Loss") && !out.contains("rtt"));
    }
    #[test]
    fn large_counters_and_latency_values_are_not_truncated() {
        let mut s = Tracker::new(Duration::from_secs(86400));
        s.total.sent = u64::MAX;
        s.total.invalid = u64::MAX;
        s.record(Event::Received(Duration::from_secs(86399)));
        let out = summary(Mode::Udp, &s);
        assert!(out.contains(&u64::MAX.to_string()));
        assert!(out.contains("86399000.000000"));
        assert!(
            out.lines()
                .filter(|line| !line.contains("rtt "))
                .all(|line| line.len() <= 80),
            "{out}"
        );
        assert!(out.contains(
            "rtt min/avg/max/mdev = 86399000.000000/86399000.000000/86399000.000000/0.000000 ms\n"
        ));
    }

    #[test]
    fn performance_output_includes_payload_bandwidth() {
        let mut s = Tracker::new(Duration::from_secs(1));
        s.sent_with_bytes(1, Instant::now(), 1000);
        s.receive_with_bytes(1, Instant::now(), 1000);
        let mut o = options::parse(["-u", "-b", "localhost"].map(str::to_owned)).unwrap();
        o.interval = Duration::from_secs(1);
        let mut out = Vec::new();
        let mut p = Printer::new(&mut out, &o, "127.0.0.1:11111".parse().unwrap()).unwrap();
        p.sample(&mut s, Duration::from_secs(1), Duration::from_secs(1))
            .unwrap();
        p.summary(&s, Duration::from_secs(1)).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("TX-kB/s") && out.contains("RX-kB/s"));
        assert!(out.contains("Payload TX/RX = 1000/1000 bytes"));
        assert!(out.contains("Avg bandwidth TX/RX = 1.00/1.00 kB/s"));
    }
}
