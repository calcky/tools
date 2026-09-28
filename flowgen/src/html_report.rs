use crate::record::{Kind, RecordingSummary, KINDS};
use serde_json::{json, Value};
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::Path;

const TEMPLATE: &str = include_str!("../assets/report.html");
const CHARTS: &str = include_str!("../assets/echarts-5.6.0.min.js");
const LICENSE: &str = include_str!("../assets/echarts-LICENSE.txt");

fn json_value(out: &mut impl Write, value: &Value) -> io::Result<()> {
    // JSON lives inside a script element. Escaping '<' prevents metadata from
    // closing that element; the UI inserts labels only through textContent.
    let text = serde_json::to_string(value).map_err(io::Error::other)?;
    out.write_all(
        text.replace('<', "\\u003c")
            .replace('>', "\\u003e")
            .replace('&', "\\u0026")
            .as_bytes(),
    )
}

pub(crate) fn metadata(dir: &Path) -> io::Result<Value> {
    let mut values = serde_json::Map::new();
    match fs::read_to_string(dir.join("run.txt")) {
        Ok(text) => {
            for line in text.lines() {
                if let Some((key, value)) = line.split_once(char::is_whitespace) {
                    values.insert(key.to_owned(), json!(value.trim()));
                }
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    Ok(Value::Object(values))
}

fn begin(out: &mut impl Write, dir: &Path, mode: &str, extra: &Value) -> io::Result<()> {
    let (head, _) = TEMPLATE
        .split_once("<!--DATA-->")
        .expect("HTML template marker");
    out.write_all(head.as_bytes())?;
    // Preserve the vendor's license in each standalone report.
    writeln!(out, "<!-- {} -->", LICENSE.replace("--", "- -"))?;
    writeln!(
        out,
        "<script>{CHARTS}</script><script id=\"report-data\" type=\"application/json\">"
    )?;
    write!(out, "{{\"mode\":")?;
    json_value(out, &json!(mode))?;
    write!(out, ",\"metadata\":")?;
    json_value(out, &metadata(dir)?)?;
    write!(out, ",\"extra\":")?;
    json_value(out, extra)?;
    write!(out, ",\"tables\":{{")
}

fn end(out: &mut impl Write) -> io::Result<()> {
    writeln!(out, "}}}}</script>")?;
    let (_, tail) = TEMPLATE
        .split_once("<!--DATA-->")
        .expect("HTML template marker");
    out.write_all(tail.as_bytes())?;
    out.flush()
}

fn csv_table(out: &mut impl Write, path: &Path) -> io::Result<()> {
    write!(out, "[")?;
    let mut reader = csv::Reader::from_path(path).map_err(io::Error::other)?;
    let headers = reader.headers().map_err(io::Error::other)?.clone();
    let role = headers.iter().position(|key| key == "role");
    let mut comma = false;
    for row in reader.records() {
        let row = row.map_err(io::Error::other)?;
        if role.is_some_and(|i| row.get(i) == Some("server")) {
            continue;
        }
        if comma {
            write!(out, ",")?;
        }
        let values: serde_json::Map<String, Value> = headers
            .iter()
            .zip(row.iter())
            .map(|(k, v)| (k.to_owned(), json!(v)))
            .collect();
        json_value(out, &Value::Object(values))?;
        comma = true;
    }
    write!(out, "]")
}

pub(crate) fn events(dir: &Path, scratch: &Path, extra: Value) -> io::Result<()> {
    let mut out = BufWriter::new(File::create(scratch.join("report.html"))?);
    begin(&mut out, dir, "events", &extra)?;
    for (i, (key, file)) in [
        ("summary", "summary.csv"),
        ("timeline", "timeseries.csv"),
        ("errors", "errors.csv"),
        ("recordings", "recordings.csv"),
        ("forward", "forward-summary.csv"),
        ("attainment", "attainment.csv"),
        ("readiness", "readiness.csv"),
    ]
    .iter()
    .enumerate()
    {
        if i > 0 {
            write!(out, ",")?;
        }
        write!(out, "\"{key}\":")?;
        csv_table(&mut out, &scratch.join(file))?;
    }
    end(&mut out)
}

pub(crate) fn summary(dir: &Path, summary: &RecordingSummary, complete: bool) -> io::Result<()> {
    let names = [
        "open",
        "ready",
        "sent",
        "response_records",
        "timeout",
        "canceled",
        "closed",
        "failed",
        "server_request",
        "server_response",
        "duplicate",
        "late",
        "invalid",
        "limited",
        "skipped",
        "reordered",
        "session_skipped",
        "error",
    ];
    let kinds = [
        Kind::Open,
        Kind::Ready,
        Kind::Sent,
        Kind::Response,
        Kind::Timeout,
        Kind::Canceled,
        Kind::Closed,
        Kind::Failed,
        Kind::ServerRequest,
        Kind::ServerResponse,
        Kind::Duplicate,
        Kind::Late,
        Kind::Invalid,
        Kind::Limited,
        Kind::Skipped,
        Kind::Reordered,
        Kind::SessionSkipped,
        Kind::Error,
    ];
    assert_eq!(names.len(), KINDS);
    let mut row = serde_json::Map::new();
    for (name, kind) in names.into_iter().zip(kinds) {
        row.insert(name.into(), json!(summary.count(kind).to_string()));
    }
    row.insert("run".into(), json!(summary.run().to_string()));
    row.insert(
        "protocol".into(),
        json!(if summary.tcp() { "tcp" } else { "udp" }),
    );
    row.insert("role".into(), json!("client"));
    row.insert("incomplete".into(), json!((!complete).to_string()));
    row.insert(
        "rtt_samples".into(),
        json!(summary.response_samples().to_string()),
    );
    for (key, value) in [
        ("rtt_min_ns", summary.response_min_ns().map(|v| v as f64)),
        ("rtt_avg_ns", summary.response_avg_ns()),
        ("rtt_max_ns", summary.response_max_ns().map(|v| v as f64)),
        ("rtt_mdev_ns", summary.response_mdev_ns()),
        (
            "rtt_p50_ns",
            summary.response_quantile_ns(0.5).map(|v| v as f64),
        ),
        (
            "rtt_p90_ns",
            summary.response_quantile_ns(0.9).map(|v| v as f64),
        ),
        (
            "rtt_p95_ns",
            summary.response_quantile_ns(0.95).map(|v| v as f64),
        ),
        (
            "rtt_p99_ns",
            summary.response_quantile_ns(0.99).map(|v| v as f64),
        ),
    ] {
        row.insert(
            key.into(),
            json!(value.map_or_else(|| "NA".into(), |v| v.to_string())),
        );
    }
    let scratch = super::analyze::Scratch::new(dir)?;
    let path = scratch.0.join("report.html");
    let mut out = BufWriter::new(File::create(&path)?);
    crate::attainment::write(dir, &scratch.0, None)?;
    begin(&mut out, dir, "summary", &json!({ "worst": [] }))?;
    write!(out, "\"summary\":[")?;
    json_value(&mut out, &Value::Object(row))?;
    write!(
        out,
        "],\"timeline\":[],\"errors\":[],\"recordings\":[],\"forward\":[],\"attainment\":"
    )?;
    csv_table(&mut out, &scratch.0.join("attainment.csv"))?;
    write!(out, ",\"readiness\":[]")?;
    end(&mut out)?;
    drop(out);
    fs::rename(path, dir.join("report.html"))?;
    fs::rename(scratch.0.join("attainment.csv"), dir.join("attainment.csv"))?;
    Ok(())
}
