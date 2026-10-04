"""Root-only lifecycle regression. Temporary objects and loopback only."""
import json
import fcntl
import os
import pathlib
import pty
import select
import selectors
import struct
import subprocess
import sys
import tempfile
import termios
import time


def run(binary, global_mode=False):
    with tempfile.TemporaryDirectory(prefix="fdtop-events-") as directory:
        executable = str(pathlib.Path(directory) / "worker")
        subprocess.run(["cc", "-O2", "-Wall", "-Wextra", "-Werror", str(pathlib.Path(__file__).with_suffix(".c")), "-lrt", "-o", executable], check=True)
        child = subprocess.Popen([executable, directory], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        tracer = None
        try:
            assert child.stdout.readline().strip() == "READY"
            scope = ["-n", "fd-event-case"] if global_mode else ["-p", str(child.pid)]
            tracer = subprocess.Popen([binary, "-e", *scope, "-d", ".2", "-c", "15", "-j"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            with selectors.DefaultSelector() as selector:
                selector.register(tracer.stdout, selectors.EVENT_READ)
                assert selector.select(20), "event collector did not start"
                first = tracer.stdout.readline()
            assert first, tracer.stderr.read()
            child.stdin.write("x\n"); child.stdin.flush()
            report, _ = child.communicate(timeout=10)
            assert child.returncode == 0, report
            output, errors = tracer.communicate(timeout=15)
            assert tracer.returncode == 0, errors
            samples = [json.loads(line) for line in (first + output).splitlines()]
            events = [e for s in samples for e in s["events"]]
            assert all(s["losses"] == [0]*4 and s["decode_errors"] == 0 and s["output_dropped"] == 0 for s in samples), samples
            if global_mode:
                inherited = [e for e in events if e["event"] == "INHERIT"]
                assert inherited and all(e["pid"] != child.pid for e in inherited), events
                assert any(e["event"] == "CLOSE" and e["reason"] == "table-release" and e["pid"] != child.pid for e in events), events
                print("PASS: global capture fork inheritance and child table release", flush=True)
                return
            assert all(e["pid"] == child.pid for e in events)
            assert any(e["event"] == "EXISTING" for e in events)
            for kind in ["FILE","EVENTFD","TIMERFD","PIPE","UNIX","UDP","TCP","EPOLL","SIGNALFD","MQ","BPFMAP","XSK"]:
                assert any(e["type"] == kind and e["event"] == "OPEN" for e in events), (kind,events)
                assert any(e["type"] == kind and e["event"] == "CLOSE" for e in events), (kind,events)
            cases = [line.split() for line in report.splitlines()]
            for kind, number in cases:
                fd = int(number)
                action = "DUP" if kind in ("DUP","REPLACE","RANGE","CLOEXEC") else "OPEN"
                if kind == "EXIT":
                    assert any(e["fd"] == fd and e["event"] == "CLOSE" and e["reason"] == "table-release" for e in events), events
                    continue
                assert any(e["fd"] == fd and e["event"] == action for e in events), (kind,number)
                assert any(e["fd"] == fd and e["event"] == "CLOSE" for e in events), (kind,number)
            assert any(e["fd"] == 160 and e["reason"] == "cloexec" for e in events)
            replacement = next(int(fd) for name,fd in cases if name == "REPLACE")
            positions = [i for i,e in enumerate(events) if e["fd"] == replacement and e["reason"] == "replace"]
            assert [events[i]["event"] for i in positions] == ["CLOSE","DUP"], positions
            generations = [e["event_object_id"] for e in events if e["event"] == "OPEN" and "short" in e["object"]]
            assert len(generations) == len(set(generations)) == 3, generations
            assert any(e["event"] == "UPDATE" and e["type"] == "UDP" for e in events)
            print("PASS: short-lived file generations, sockets/accept/SCM_RIGHTS, pipe, MQ, anon/BPF/XSK, dup overwrite, close_range, CLOEXEC and exit", flush=True)
        finally:
            for process in (tracer, child):
                if process is not None and process.poll() is None:
                    process.terminate(); process.wait(timeout=10)


def terminal(binary):
    target = subprocess.Popen(["sleep", "30"])
    try:
        for direct, quit_key in ((False, b"q"), (True, b"\x03")):
            master, slave = pty.openpty()
            before = termios.tcgetattr(slave)
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH",24,80,0,0))
            process = subprocess.Popen([binary, "-p", str(target.pid), *(["-e"] if direct else [])], stdin=slave,stdout=slave,stderr=slave,
                                       env={**os.environ,"TERM":"xterm-256color","NO_COLOR":"1"})
            def read_for(seconds):
                output=b""; end=time.monotonic()+seconds
                while time.monotonic()<end:
                    if select.select([master],[],[],.1)[0]: output+=os.read(master,65536)
                return output
            try:
                output=read_for(2)
                if not direct:
                    os.write(master,b"e"); output=read_for(1)
                # Incremental terminal redraws can split header words with cursor moves.
                assert b"events" in output and b"EXISTING" in output,output[-3000:]
                os.write(master,b"jkh"); read_for(.3)
                os.write(master,b"h")
                fcntl.ioctl(slave,termios.TIOCSWINSZ,struct.pack("HHHH",30,120,0,0))
                read_for(.3)
                os.write(master,b"e"); assert b"ROPS/s" in read_for(.5)
                os.write(master,b"e"); read_for(.3)
                os.write(master,quit_key); read_for(.5)
                assert process.wait(timeout=5)==0
                assert termios.tcgetattr(slave)==before
            finally:
                if process.poll() is None: process.kill();process.wait()
                os.close(master);os.close(slave)
        print("PASS: event -e/e toggle, 80/120 columns, help, NO_COLOR, q/Ctrl+C restore",flush=True)
    finally:
        target.terminate(); target.wait()


if __name__ == "__main__":
    run(sys.argv[1])
    run(sys.argv[1], global_mode=True)
    terminal(sys.argv[1])
