"""Root-only loopback metadata refresh regression; no system settings changed."""
import json
import os
import selectors
import socket
import subprocess
import sys


def run(binary, latency):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client, \
         socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as first, \
         socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as second, \
         socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as unix, \
         socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0) as netlink, \
         socket.socket(44, socket.SOCK_RAW, 0) as xsk:
        first.bind(("127.0.0.1", 0))
        second.bind(("127.0.0.1", 0))
        name = f"fdtop-meta-{os.getpid()}"
        unix.bind("\0" + name)
        unix.setblocking(False)
        netlink.bind((0, 0))
        client.connect(first.getsockname())
        flags = ["-l"] if latency else []
        tracer = subprocess.Popen([binary, *flags, "-p", str(os.getpid()), "-d", "0.2", "-c", "25", "-j"],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        samples = []
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(tracer.stdout, selectors.EVENT_READ)
                for index in range(25):
                    assert selector.select(20), "collector stalled"
                    line = tracer.stdout.readline()
                    assert line, tracer.stderr.read()
                    samples.append(json.loads(line))
                    if index == 9:
                        client.connect(second.getsockname())
                    client.send(b"metadata")
                    try:
                        unix.recv(1)
                    except BlockingIOError:
                        pass
                    for control in (netlink, xsk):
                        try:
                            control.recv(1, socket.MSG_DONTWAIT)
                        except OSError:
                            pass
            assert tracer.wait(timeout=10) == 0, tracer.stderr.read()
            udp = [r for s in samples for r in s["rows"] if r["fd"] == client.fileno()]
            for sock in (first, second):
                endpoint = "%s:%s" % sock.getsockname()
                assert any(r["metadata_source"] == "live" and r["object"].endswith(endpoint) for r in udp), udp
            unix_rows = [r for s in samples for r in s["rows"] if r["fd"] == unix.fileno()]
            assert any(f"unix:@{name}" in r["object"] and r["metadata_source"] == "live" for r in unix_rows), unix_rows
            assert any(r["state"] == "open" and r["metadata_source"] == "live" for r in udp)
            assert all(r["inode"] > 0 for r in udp)
            rows = [r for s in samples for r in s["rows"] if r["fd"] == netlink.fileno()]
            assert any("netlink:pid=" in r["object"] and "protocol=0" in r["object"] and r["metadata_source"] == "live" for r in rows), rows[-1:]
            rows = [r for s in samples for r in s["rows"] if r["fd"] == xsk.fileno()]
            if any(r["object"] == "XSK unbound" and r["metadata_source"] == "live" for r in rows):
                print("PASS: unbound XSK diagnostics", flush=True)
            else:
                assert rows and all(r["metadata_source"] in ("observed", "proc") and
                                   "XDP socket diagnostics unavailable" in (r["metadata_error"] or "") for r in rows), rows[-1:]
                print("PASS: explicit missing XSK diagnostic module fallback; live XSK not verified", flush=True)
            print("PASS:", "latency" if latency else "light", "UDP reconnect, UNIX name, NETLINK, live/cache status", flush=True)
        finally:
            if tracer.poll() is None:
                tracer.terminate()
                tracer.wait(timeout=10)


if __name__ == "__main__":
    for mode in (False, True):
        run(sys.argv[1], mode)
