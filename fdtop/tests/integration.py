"""Run as root on a disposable Linux test host; only temp files and loopback."""
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


def run(binary, latency):
    flags = ["-l"] if latency else []
    print("MODE:", "latency" if latency else "light", flush=True)
    source = pathlib.Path(__file__).with_name("workload.c")
    with tempfile.TemporaryDirectory(prefix="fdtop-fixture-") as directory:
        worker_path = str(pathlib.Path(directory) / "worker")
        subprocess.run(["cc", "-O2", "-Wall", "-Wextra", "-Werror", str(source),
                        "-pthread", "-lrt", "-o", worker_path], check=True)
        worker = subprocess.Popen([worker_path, directory], stdin=subprocess.PIPE)
        tracer = None
        try:
            tracer = subprocess.Popen([binary, *flags, "-p", str(worker.pid), "-d", "0.2", "-c", "15", "-j"],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            with selectors.DefaultSelector() as selector:
                selector.register(tracer.stdout, selectors.EVENT_READ)
                assert selector.select(20), "collector did not start"
                first = tracer.stdout.readline()
            if not first:
                raise AssertionError(tracer.stderr.read())
            json.loads(first)
            worker.stdin.write(b"x")
            worker.stdin.close()
            output, errors = tracer.communicate(timeout=15)
            assert worker.wait(timeout=10) == 0
            assert tracer.returncode == 0, errors
            samples = [json.loads(line) for line in (first + output).splitlines()]
            assert all(s["latency"] == latency for s in samples)
            assert all(s["gaps"] == [0]*5 for s in samples), [s["gaps"] for s in samples]
            rows = {}
            for sample in samples:
                for row in sample["rows"]:
                    if row["object_id"] != 0 or row["state"] == "invalid":
                        rows[(row["fd"], row["object_id"])] = row
            def fd(n):
                return [r for (number, _), r in rows.items() if number == n]
            def check(n, kind, read, write):
                values = fd(n)
                assert len(values) == 1, (n, values)
                r = values[0]
                assert (r["type"], r["total_read"]["bytes"], r["total_write"]["bytes"]) == (kind, read, write), r
            check(100, "CHAR", 0, 123)
            assert fd(100)[0]["total_read"]["ops"] == 0
            assert fd(100)[0]["total_write"]["ops"] == 1
            assert sorted(r["total_write"]["bytes"] for r in fd(101)) == [7,4256], fd(101)
            first_file = next(r for r in fd(101) if r["total_write"]["bytes"] == 4256)
            assert first_file["total_read"]["bytes"] == 224
            check(102,"FILE",0,11)
            assert first_file["object_id"] == fd(102)[0]["object_id"]
            check(104,"PIPE",4,0)
            assert any(r["fd"] == 104 and r["pending"] and
                       (r["oldest_ms"] >= 200 if latency else r["oldest_ms"] is None)
                       for s in samples for r in s["rows"])
            if latency:
                assert fd(104)[0]["total_read"]["capture_max_ms"] >= 200
            else:
                for s in samples:
                    for r in s["rows"]:
                        assert r["oldest_ms"] is None
                        for direction in ("read", "write", "total_read", "total_write"):
                            for field in ("elapsed_ns", "avg_ms", "p95_upper_ms", "p99_upper_ms", "capture_max_ms"):
                                assert r[direction][field] is None, r
            check(106,"UNIX",0,12)
            check(107,"UNIX",12,0)
            check(108,"UDP",0,14)
            check(109,"UDP",14,0)
            check(110,"TCP",0,9)
            check(111,"TCP",9,0)
            check(112,"MQ",7,7)
            assert fd(112)[0]["total_read"]["again"] == 1
            assert fd(112)[0]["total_read"]["errors"] == 0
            assert fd(199)[0]["total_read"]["errors"] == 1
            check(113,"FILE",56,0)
            check(114,"UNIX",0,32)
            check(116,"PIPE",32,0)
            check(119,"PIPE",0,32)
            check(120,"FILE",0,24)
            check(121,"EVENTFD",8,8)
            assert fd(121)[0]["total_read"]["again"] == 1
            check(122,"TIMERFD",8,0)
            check(123,"SIGNALFD",128,0)
            for number, name in [(121,"eventfd"),(122,"timerfd"),(123,"signalfd")]:
                assert fd(number)[0]["object"] == f"anon_inode:[{name}]"
            print("PASS: eventfd/timerfd/signalfd types and exact byte counts after close")
            print("PASS: file/reuse/dup, char, blocked pipe, TCP/UDP/UNIX, vectors, mmsg, MQ, EAGAIN/EBADF, sendfile/splice/tee/copy")
        finally:
            for process in [tracer, worker]:
                if process is not None and process.poll() is None:
                    process.kill()
                    process.wait()

        worker = subprocess.Popen([worker_path, directory, "churn"], stdin=subprocess.PIPE)
        tracer = None
        try:
            tracer = subprocess.Popen([binary,*flags,"-p",str(worker.pid),"-d","0.1","-c","45","-j"],
                                      stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            with selectors.DefaultSelector() as selector:
                selector.register(tracer.stdout,selectors.EVENT_READ)
                assert selector.select(20), "churn collector did not start"
                first=tracer.stdout.readline()
            assert first, tracer.stderr.read()
            worker.stdin.write(b"x")
            worker.stdin.close()
            output, errors=tracer.communicate(timeout=30)
            assert worker.wait(timeout=5) == 0
            assert tracer.returncode == 0, errors
            samples=[json.loads(line) for line in (first+output).splitlines()]
            assert all(s["gaps"] == [0]*5 for s in samples), [s["gaps"] for s in samples]
            total=sum(r["write"]["bytes"] for s in samples for r in s["rows"] if r["fd"] == 100)
            assert total == 20000,total
            assert samples[-1]["tracked"] == 0,samples[-1]["tracked"]
            print("PASS: 20,000 short-lived FD objects, exact bytes, maps reclaimed")
        finally:
            for process in [tracer,worker]:
                if process is not None and process.poll() is None:
                    process.kill()
                    process.wait()

    terminal_test(binary, flags)


def terminal_test(binary, flags):
    for key in [b"q",b"\x03"]:
        master,slave=pty.openpty()
        before=termios.tcgetattr(slave)
        process=None
        try:
            fcntl.ioctl(slave,termios.TIOCSWINSZ,struct.pack("HHHH",24,80,0,0))
            process=subprocess.Popen([binary,*flags,"-p",str(os.getpid()),"-d","0.1"],
                stdin=slave,stdout=slave,stderr=slave,
                env={**os.environ,"TERM":"xterm-256color","NO_COLOR":"1"})
            def read_for(seconds):
                data=b""
                deadline=time.monotonic()+seconds
                while time.monotonic()<deadline:
                    if select.select([master],[],[],0.1)[0]:
                        data+=os.read(master,65536)
                return data
            output=read_for(1)
            assert b"fdtop" in output,output[-1000:]
            os.write(master,b"h")
            assert b"Help" in read_for(0.3)
            os.write(master,b"h")
            fcntl.ioctl(slave,termios.TIOCSWINSZ,struct.pack("HHHH",30,120,0,0))
            read_for(0.3)
            os.write(master,key)
            read_for(0.3)
            assert process.wait(timeout=5) == 0
            assert termios.tcgetattr(slave) == before,"terminal modes not restored"
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                process.wait()
            os.close(master)
            os.close(slave)
    print("PASS: PTY 80/120 columns, help, resize, NO_COLOR, q/Ctrl+C restore")


if __name__ == "__main__":
    for latency in (False, True):
        run(str(pathlib.Path(sys.argv[1]).resolve()), latency)
