"""Bounded 30s active + 10s idle collector memory/CPU observation."""
import json
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time
from benchmark import proc

binary, directory = sys.argv[1:]
out = Path(directory)
worker = subprocess.Popen([str(out / "worker"), "tcp", "30"], stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, text=True)
tracer = subprocess.Popen([binary, "-p", str(worker.pid), "-d", "1", "-j"],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
samples = []
ready = threading.Event()


def drain():
    for line in tracer.stdout:
        sample = json.loads(line)
        sample["collector"] = proc(tracer.pid)
        samples.append(sample)
        ready.set()


thread = threading.Thread(target=drain)
thread.start()
try:
    assert ready.wait(20), "collector startup timeout"
    output, _ = worker.communicate("x", timeout=40)
    assert worker.returncode == 0
    active_end = len(samples)
    time.sleep(10)
    tracer.send_signal(signal.SIGINT)
    tracer.wait(timeout=10)
    thread.join(timeout=5)
    assert tracer.returncode == 0, tracer.stderr.read()
    (out / "soak.json").write_text(json.dumps({"workload": json.loads(output),
        "active_end": active_end, "samples": samples}, indent=2)+"\n")
    print(json.dumps({"samples": len(samples), "active_end": active_end,
        "rss_kib_min": min(s["collector"]["rss_kib"] for s in samples),
        "rss_kib_max": max(s["collector"]["rss_kib"] for s in samples),
        "gaps": samples[-1]["gaps"]}), flush=True)
finally:
    for process in (worker, tracer):
        if process.poll() is None:
            process.kill()
            process.wait()
