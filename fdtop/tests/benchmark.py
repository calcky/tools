"""Run as root on a quiet Linux host. Results and raw samples go to OUTDIR."""
import json
import hashlib
import os
from pathlib import Path
import selectors
import signal
import statistics
import subprocess
import sys
import threading
import time


def proc(pid):
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return {"cpu": (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK"),
            "rss_kib": int(fields[21]) * os.sysconf("SC_PAGE_SIZE") / 1024}


def run(binary, out, previous=None):
    out.mkdir(parents=True, exist_ok=True)
    worker_bin = out / "worker"
    subprocess.run(["cc", "-O2", "-Wall", "-Wextra", "-Werror", "-pthread",
                    str(Path(__file__).with_name("bench.c")), "-o", str(worker_bin)], check=True)
    results = []
    cpus = sorted(os.sched_getaffinity(0))[:2]
    cases = ["baseline", "global", "pid", "latency-global", "latency-pid"]
    if previous:
        cases += ["old-global", "old-pid"]
    (out / "environment.json").write_text(json.dumps({
        "uname": list(os.uname()), "worker_cpus": cpus,
        "binary": binary, "previous": previous,
        "sha256": {p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
                   for p in (binary, previous) if p},
    }, indent=2)+"\n")
    for repeat in range(3):
        for workload in ("file", "pipe", "tcp", "udp"):
            modes = cases[:]
            modes = modes[repeat:] + modes[:repeat]
            for mode in modes:
                name = f"{workload}-{mode}-{repeat}"
                worker = subprocess.Popen([str(worker_bin), workload, "3"], stdin=subprocess.PIPE,
                                          stdout=subprocess.PIPE, text=True)
                tracer = None
                samples = []
                try:
                    os.sched_setaffinity(worker.pid, cpus)
                    if mode != "baseline":
                        args = [previous if mode.startswith("old-") else binary, "-d", "1", "-j"]
                        if mode.startswith("latency-"):
                            args.append("-l")
                        if mode.endswith("pid"):
                            args += ["-p", str(worker.pid)]
                        tracer = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                        with selectors.DefaultSelector() as selector:
                            selector.register(tracer.stdout, selectors.EVENT_READ)
                            assert selector.select(20), "tracer startup timeout"
                            first = tracer.stdout.readline()
                        assert first, "tracer failed to start"
                        samples.append(json.loads(first))
                        def drain():
                            for line in tracer.stdout:
                                samples.append(json.loads(line))
                        thread = threading.Thread(target=drain)
                        thread.start()
                        before = proc(tracer.pid)
                    began = time.monotonic()
                    output, _ = worker.communicate("x", timeout=15)
                    assert worker.returncode == 0
                    result = json.loads(output)
                    result.update(workload=workload, mode=mode, repeat=repeat)
                    if tracer:
                        after = proc(tracer.pid)
                        result.update(tracer_cpu_pct=100*(after["cpu"]-before["cpu"])/(time.monotonic()-began),
                                      tracer_rss_kib=after["rss_kib"])
                        tracer.send_signal(signal.SIGINT)
                        tracer.wait(timeout=10)
                        thread.join(timeout=5)
                        assert tracer.returncode == 0, tracer.stderr.read()
                        result["gaps"] = [max(s["gaps"][i] for s in samples) for i in range(5)]
                        (out / f"{name}.jsonl").write_text("\n".join(map(json.dumps, samples))+"\n")
                    results.append(result)
                    (out / "results.json").write_text(json.dumps(results, indent=2)+"\n")
                    print(name, round(result["received"]/result["seconds"]/1e6, 1), "MB/s", flush=True)
                finally:
                    for process in (worker, tracer):
                        if process and process.poll() is None:
                            process.kill()
                            process.wait()
    lines = ["# fdtop overhead benchmark", "", "Three interleaved 3-second runs per case; median received MB/s (decimal).",
             "Cached file: 4KiB pread/pwrite; pipe/TCP: 4KiB writes; UDP: 1472B datagrams, actual received bytes.",
             "CPU seconds include workload threads and BPF execution, not just collector userspace.", "",
             "| Workload | Mode | MB/s | Range MB/s | vs baseline | CPU ns/received KiB | Collector CPU % |", "|---|---|---:|---:|---:|---:|---:|"]
    for workload in ("file", "pipe", "tcp", "udp"):
        baseline = statistics.median(r["received"]/r["seconds"] for r in results if r["workload"] == workload and r["mode"] == "baseline")
        for mode in cases:
            rows = [r for r in results if r["workload"] == workload and r["mode"] == mode]
            rates = [r["received"]/r["seconds"] for r in rows]
            rate = statistics.median(rates)
            cpu = statistics.median(r["cpu_seconds"]*1e9/(r["received"]/1024) for r in rows)
            collector = statistics.median(r.get("tracer_cpu_pct", 0) for r in rows)
            lines.append(f"| {workload} | {mode} | {rate/1e6:.1f} | {min(rates)/1e6:.1f}-{max(rates)/1e6:.1f} | {(rate/baseline-1)*100:+.1f}% | {cpu:.0f} | {collector:.2f} |")
    lines += ["", "## Light versus latency", "",
              "| Workload | Scope | Latency MB/s | Light MB/s | Change |",
              "|---|---|---:|---:|---:|"]
    for workload in ("file", "pipe", "tcp", "udp"):
        for scope in ("global", "pid"):
            full, light = [statistics.median(r["received"]/r["seconds"]/1e6 for r in results
                if r["workload"] == workload and r["mode"] == name)
                for name in ("latency-"+scope, scope)]
            lines.append(f"| {workload} | {scope} | {full:.1f} | {light:.1f} | {(light/full-1)*100:+.1f}% |")
    if previous:
        lines += ["", "## Same-run comparison", "",
                  "| Workload | Mode | Old MB/s | New MB/s | Change |",
                  "|---|---|---:|---:|---:|"]
        for workload in ("file", "pipe", "tcp", "udp"):
            for mode in ("global", "pid"):
                medians = [statistics.median(r["received"]/r["seconds"]/1e6 for r in results
                    if r["workload"] == workload and r["mode"] == name)
                    for name in ("old-"+mode, mode)]
                old, new = medians
                lines.append(f"| {workload} | {mode} | {old:.1f} | {new:.1f} | {(new/old-1)*100:+.1f}% |")
    (out / "report.md").write_text("\n".join(lines)+"\n")


if __name__ == "__main__":
    run(str(Path(sys.argv[1]).resolve()), Path(sys.argv[2]).resolve(),
        str(Path(sys.argv[3]).resolve()) if len(sys.argv) > 3 else None)
