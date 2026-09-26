"""Unprivileged static-file and controlling-terminal regression checks.

Requires python3-pyte. Run with CTTOP_BIN pointing to the compiled executable.
"""
import fcntl
import os
import pty
import select
import signal
import struct
import subprocess as sp
import tempfile
import termios
import time
from pathlib import Path

import pyte

BIN = os.environ.get("CTTOP_BIN", str(Path(__file__).resolve().parents[1] / "target/release/cttop"))
DUMP = (
    "tcp 6 400 ESTABLISHED src=10.0.0.2 dst=198.51.100.2 sport=1234 dport=443 "
    "packets=12 bytes=1200 src=198.51.100.2 dst=203.0.113.1 sport=443 dport=40000 "
    "packets=8 bytes=800 [ASSURED] mark=16 use=1\n"
    "ipv6 10 udp 17 29 src=::1 dst=::2 sport=1234 dport=53 [UNREPLIED] "
    "src=::2 dst=::1 sport=53 dport=1234 mark=0\n"
)


def report(args, data=None):
    return sp.run([BIN, *args], input=data, text=True, capture_output=True, timeout=5, check=True).stdout


def tui(path, piped, quit_signal=False):
    master, slave = pty.openpty()
    before = termios.tcgetattr(slave)
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 36, 160, 0, 0))

    def controlling_terminal():
        os.setsid()
        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)

    proc = sp.Popen([BIN, "-f", *([] if piped else [str(path)]), "-g", "mark"],
                    stdin=sp.PIPE if piped else slave, stdout=slave, stderr=slave,
                    preexec_fn=controlling_terminal, pass_fds=(slave,),
                    env=dict(os.environ, TERM="xterm-256color", NO_COLOR="1"))
    screen = pyte.Screen(160, 36)
    stream = pyte.ByteStream(screen)

    def wait_for(text):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if select.select([master], [], [], .1)[0]:
                stream.feed(os.read(master, 65536))
            if text in "\n".join(screen.display):
                return
            assert proc.poll() is None, "terminal exited early"
        raise AssertionError((text, screen.display))

    try:
        if piped:
            proc.stdin.write(DUMP.encode())
            proc.stdin.close()
        wait_for("STATIC")
        wait_for("0x10")
        assert "LIVE" not in "\n".join(screen.display)
        os.write(master, b"/0x10\r")
        wait_for("1 groups")
        os.write(master, b"\r")
        wait_for("CT 1-1 / 1")
        wait_for("1200")
        os.write(master, b"n")
        wait_for("203.0.113.1:40000")
        os.write(master, b"h")
        wait_for("Help | h/Esc close")
        os.write(master, b"h")
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
        screen.resize(24, 80)
        proc.send_signal(signal.SIGWINCH)
        wait_for("STATIC")
        if quit_signal:
            proc.send_signal(signal.SIGTERM)
        else:
            os.write(master, b"q")
        proc.wait(timeout=3)
        assert proc.returncode == 0
        assert termios.tcgetattr(slave) == before, "terminal settings not restored"
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        os.close(master)
        os.close(slave)


with tempfile.TemporaryDirectory() as directory:
    path = Path(directory) / "connections.txt"
    path.write_text(DUMP)
    for args, data in [(["-f", str(path)], None), (["-f"], DUMP), (["-f", "-"], DUMP)]:
        output = report([*args, "-g", "none", "-c", "9"], data)
        assert output.count("cttop |") == 1
        assert "STATIC" in output and "2 connections" in output
        assert "0x10" in output and "1200" in output
        assert "\x1b" not in output
    output = report(["-f", str(path), "-N", "-s", "10.0.0.2", "-g", "none"])
    assert "203.0.113.1:40000" in output and "1 connections" in output
    assert "::1" not in output
    error = sp.run([BIN, "-f"], input="# comment\nbad\n", text=True, capture_output=True, timeout=3)
    assert error.returncode != 0 and "stdin:2:" in error.stderr
    assert "No matching sessions" in report(["-f"], "")
    assert "No such file" in sp.run([BIN, "-f", str(path) + ".missing"], capture_output=True, text=True).stderr
    print("PASS file/stdin reports, single report exit, counters, NAT, filters, invalid/empty/missing files", flush=True)
    for piped, sig in [(False, False), (True, False), (True, True)]:
        tui(path, piped, sig)
    print("PASS unprivileged file/pipeline TUI, grouping, drilldown, search, NAT, help, resize, q/SIGTERM restore", flush=True)
