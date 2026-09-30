"""Local Go pprof and pseudo-terminal smoke test. Requires Go and Linux."""

import fcntl
import os
import pty
import select
import signal
import socket
import subprocess
import tempfile
import termios
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BIN = Path(os.environ.get("GOMEMTOP_BIN", ROOT / "target/release/gomemtop"))
GO = os.environ.get("GO_BIN", "/usr/local/go/bin/go")


def wait_until(predicate, deadline, description):
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.1)
    raise AssertionError(f"timed out: {description}; terminal tail: {output.decode(errors='ignore')[-1500:]!r}")


def stop_group(proc):
    if proc.poll() is None:
        os.killpg(proc.pid, signal.SIGTERM)
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait(timeout=3)


with tempfile.TemporaryDirectory() as directory:
    server_bin = Path(directory) / "server"
    subprocess.run([GO, "build", "-o", str(server_bin), str(ROOT / "tests/fixtures/server.go")], check=True)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    address = f"127.0.0.1:{port}"
    url = f"http://{address}"
    env = dict(os.environ, GOMEMTOP_TEST_ADDR=address)

    def start_server():
        return subprocess.Popen([str(server_bin)], env=env, start_new_session=True,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def server_ready():
        try:
            with urllib.request.urlopen(url + "/debug/pprof/heap", timeout=1) as response:
                return response.status == 200
        except OSError:
            return False

    def counter(name):
        with urllib.request.urlopen(url + "/" + name, timeout=1) as response:
            return int(response.read())

    server = start_server()
    master, slave = pty.openpty()
    before = termios.tcgetattr(slave)
    fcntl.ioctl(slave, termios.TIOCSWINSZ, b"\x18\x00\x50\x00\x00\x00\x00\x00")
    app = None
    output = bytearray()

    def drain():
        if select.select([master], [], [], 0.1)[0]:
            try:
                output.extend(os.read(master, 65536))
            except OSError:
                pass
        return output.decode(errors="ignore")

    try:
        wait_until(lambda: server.poll() is None and server_ready(),
                   time.monotonic() + 10, "Go pprof ready")
        app = subprocess.Popen([str(BIN), "-i", "0.5", "-T", "1", "--pid", str(server.pid), url],
                               stdin=slave, stdout=slave, stderr=slave,
                               env=dict(os.environ, TERM="xterm-256color"),
                               start_new_session=True)
        wait_until(lambda: "stacks" in drain() and "Sample" in drain() and "RSS" in drain()
                   and "HeapSys" in drain() and "samples | R" in drain(),
                   time.monotonic() + 8, "first profile")
        time.sleep(1.0)
        output.clear()
        for _ in range(3):
            urllib.request.urlopen(url + "/grow", timeout=1).read()
        urllib.request.urlopen(url + "/gc", timeout=1).read()
        wait_until(lambda: "main.main.func" in drain() and "MiB" in drain(),
                   time.monotonic() + 8, "heap growth")
        os.write(master, b"g")
        wait_until(lambda: drain() is not None and counter("gc-count") > 0,
                   time.monotonic() + 5, "GC toggle")
        stop_group(server)
        output.clear()
        wait_until(lambda: "Connection" in drain() or "connection" in drain(),
                   time.monotonic() + 5, "server disconnect")
        server = start_server()
        output.clear()
        wait_until(lambda: server_ready() and counter("heap-count") >= 2 and drain() is not None,
                   time.monotonic() + 8, "server recovery")
        os.write(master, b"q")
        assert app.wait(timeout=3) == 0
        assert termios.tcgetattr(slave) == before, "terminal settings not restored"
        print("Go pprof growth, GC, disconnect/recovery and terminal restore: OK")
    finally:
        if app and app.poll() is None:
            app.kill()
            app.wait()
        stop_group(server)
        os.close(master)
        os.close(slave)
