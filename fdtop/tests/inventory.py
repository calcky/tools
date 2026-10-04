"""Root-only selected-PID FD inventory regression, using idle local objects."""
import json
import os
import pathlib
import select
import socket
import subprocess
import sys


def worker():
    file = open("/dev/null", "rb")
    pipe = os.pipe()
    event = os.eventfd(0)
    epoll = select.epoll()
    tcp = socket.socket()
    tcp.bind(("127.0.0.1", 0))
    tcp.listen()
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", 0))
    unix = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    unix.bind("\0fdtop-idle-" + str(os.getpid()))
    expected = {file.fileno(): ("CHAR", "r"), pipe[0]: ("PIPE", "r"),
                pipe[1]: ("PIPE", "w"), event: ("EVENTFD", "rw"),
                epoll.fileno(): ("EPOLL", "rw"), tcp.fileno(): ("TCP", "rw"),
                udp.fileno(): ("UDP", "rw"), unix.fileno(): ("UNIX", "rw")}
    print(json.dumps(expected), flush=True)
    sys.stdin.read(1)


def run(binary, latency):
    child = subprocess.Popen([sys.executable, __file__, "worker"], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, text=True)
    try:
        expected = json.loads(child.stdout.readline())
        proc_fds = {int(p.name) for p in pathlib.Path(f"/proc/{child.pid}/fd").iterdir()}
        flags = ["-l"] if latency else []
        command = [binary, *flags, "-p", str(child.pid), "-c", "2", "-d", ".2", "-j"]
        result = subprocess.run(command, capture_output=True, text=True, timeout=20)
        assert result.returncode == 0, result.stderr
        for sample in map(json.loads, result.stdout.splitlines()):
            assert sample["inventory_error"] is None, sample["inventory_error"]
            rows = {r["fd"]: r for r in sample["rows"] if r["state"] == "open"}
            assert set(rows) == proc_fds, (set(rows), proc_fds)
            for number, (kind, access) in expected.items():
                row = rows[int(number)]
                assert (row["type"], row["access"]) == (kind, access), row
                assert row["read_ops_s"] == row["write_ops_s"] == 0, row
                assert row["read_bytes_s"] == row["write_bytes_s"] == 0, row
                assert row["metadata_error"] is None, row
                if kind == "TCP":
                    assert "(listen)" in row["object"], row
                if kind == "UNIX":
                    assert "unix:@fdtop-idle-" in row["object"], row
        result = subprocess.run([*command, "-t", "tcp"], capture_output=True, text=True, timeout=20)
        assert result.returncode == 0, result.stderr
        assert all(len(s["rows"]) == 1 and s["rows"][0]["type"] == "TCP"
                   for s in map(json.loads, result.stdout.splitlines()))
        print("PASS:", "latency" if latency else "light", "full idle FD inventory, modes, socket names and filtering", flush=True)
    finally:
        child.stdin.close()
        child.wait(timeout=5)


if __name__ == "__main__":
    if sys.argv[1] == "worker":
        worker()
    else:
        for mode in (False, True):
            run(sys.argv[1], mode)
