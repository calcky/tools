"""Run inside an isolated disposable network namespace with CAP_NET_ADMIN.

The test adds OUTPUT firewall rules only in that namespace. Never run directly
on a production host. CTTOP_LIVE_ISOLATED=1 is required. Enable accounting and
timestamps at container creation with --sysctl to test those optional fields.
"""
import fcntl
import os
import pty
import select
import signal
import socket
import struct
import subprocess as sp
import termios
import threading
import time
import codecs
import pyte


assert os.environ.get("CTTOP_LIVE_ISOLATED") == "1", "isolated namespace required"
BIN = os.environ.get("CTTOP_BIN", "/cttop-src/target/debug/cttop")


def cmd(*args):
    return sp.run(args, check=True, text=True, capture_output=True).stdout


def reports(*args):
    return sp.run([BIN, "-b", "-i", ".2", "-r", "1", "-c", "2", *args],
                  check=True, text=True, capture_output=True, timeout=10).stdout


stop = threading.Event()
sockets = []
clients = []
threads = []


def server(family, kind, address):
    sock = socket.socket(family, kind)
    sock.bind((address, 0))
    sock.settimeout(.1)
    sockets.append(sock)
    if kind == socket.SOCK_STREAM:
        sock.listen()

    def loop():
        accepted = []
        try:
            while not stop.is_set():
                try:
                    if kind == socket.SOCK_STREAM:
                        conn, _ = sock.accept()
                        conn.settimeout(.1)
                        accepted.append(conn)
                        conn.recv(128)
                        conn.sendall(b"response")
                    else:
                        data, peer = sock.recvfrom(128)
                        sock.sendto(data, peer)
                except socket.timeout:
                    pass
        finally:
            for conn in accepted:
                conn.close()

    thread = threading.Thread(target=loop)
    thread.start()
    threads.append(thread)
    return sock.getsockname()[1]


try:
    cmd("iptables", "-A", "OUTPUT", "-m", "conntrack", "--ctstate", "NEW,ESTABLISHED", "-j", "ACCEPT")
    cmd("ip6tables", "-A", "OUTPUT", "-m", "conntrack", "--ctstate", "NEW,ESTABLISHED", "-j", "ACCEPT")
    for family, address in [(socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")]:
        for kind, name in [(socket.SOCK_STREAM, "tcp"), (socket.SOCK_DGRAM, "udp")]:
            port = server(family, kind, address)
            client = socket.socket(family, kind)
            client.settimeout(2)
            client.connect((address, port))
            client.send(b"request")
            assert client.recv(128)
            clients.append(client)
            output = reports("-g", "dst,dport,proto", "-p", name, "-D", str(port))
            assert f"{address} | {port} | {name}" in output, output
            assert "No matching sessions" not in output, output
            assert "\x1b" not in output
            print(f"PASS {address} {name} original grouping", flush=True)
            raw = reports("-g", "none", "-p", name, "-D", str(port))
            rows = [line for line in raw.splitlines() if line.startswith(name + " ")]
            assert len(rows) >= 2 and all(f":{port} |" in line for line in rows), raw
            assert "group none (individual CT)" in raw, raw
            print(f"PASS {address} {name} individual CT reports", flush=True)
            for style in ["default", "extended"]:
                dump = cmd("conntrack", "-L", "-f", "ipv4" if family == socket.AF_INET else "ipv6",
                           "-p", name, "--dport", str(port), *([] if style == "default" else ["-o", style]))
                saved = sp.run([BIN, "-f", "-g", "none"], input=dump, text=True,
                               capture_output=True, check=True, timeout=5).stdout
                assert "STATIC" in saved and f":{port} |" in saved, saved
                assert "1 connections" in saved, saved
            print(f"PASS real conntrack default/extended import: {address} {name}", flush=True)

    mark_port = server(socket.AF_INET, socket.SOCK_STREAM, "127.0.0.1")
    marked = socket.socket()
    marked.settimeout(2)
    marked.connect(("127.0.0.1", mark_port))
    marked.sendall(b"mark")
    assert marked.recv(128)
    clients.append(marked)
    cmd("conntrack", "-U", "-p", "tcp", "--dport", str(mark_port), "--mark", "16")
    output = reports("-g", "mark,proto", "-p", "tcp", "-D", str(mark_port))
    assert "0x10 | tcp" in output, output
    raw = reports("-g", "none", "-p", "tcp", "-D", str(mark_port))
    assert " | 0x10 | " in raw, raw
    mark_monitor = sp.Popen(
        [BIN, "-b", "-g", "mark", "-p", "tcp", "-D", str(mark_port),
         "-i", ".2", "-r", "1", "-c", "10"],
        stdout=sp.PIPE, stderr=sp.PIPE, text=True)
    time.sleep(.5)
    cmd("conntrack", "-U", "-p", "tcp", "--dport", str(mark_port), "--mark", "32")
    output, error = mark_monitor.communicate(timeout=8)
    assert mark_monitor.returncode == 0, error
    assert "0x10" in output and "0x20" in output, output
    cmd("conntrack", "-U", "-p", "tcp", "--dport", str(mark_port), "--mark", "0")
    output = reports("-N", "-g", "mark", "-p", "tcp", "-D", str(mark_port))
    assert "0x0 " in output, output
    print("PASS conntrack marks: individual/composite groups/live updates/zero", flush=True)

    traffic_port = server(socket.AF_INET, socket.SOCK_DGRAM, "127.0.0.1")
    traffic_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    traffic_client.settimeout(1)
    traffic_client.connect(("127.0.0.1", traffic_port))
    traffic_stop = threading.Event()
    def send_traffic():
        while not traffic_stop.is_set():
            traffic_client.send(b"x" * 100)
            traffic_client.recv(128)
            traffic_stop.wait(.05)
    sender = threading.Thread(target=send_traffic)
    sender.start()
    try:
        output = sp.run([BIN, "-b", "-i", ".5", "-r", "1", "-c", "8", "-g", "proto",
                         "-p", "udp", "-D", str(traffic_port)],
                        check=True, text=True, capture_output=True, timeout=10).stdout
        traffic_rows = [[v.strip() for v in line.split("|")]
                        for line in output.splitlines() if line.startswith("udp ")]
        assert traffic_rows, output
        if open("/proc/sys/net/netfilter/nf_conntrack_acct").read().strip() == "1":
            assert traffic_rows[0][7:9] == ["N/A", "N/A"], output
            assert any(all(v not in ("N/A", "0.0b/s") for v in row[7:9])
                       for row in traffic_rows), output
            assert int(traffic_rows[-1][9]) > int(traffic_rows[0][9]) > 0, output
            assert int(traffic_rows[-1][10]) > int(traffic_rows[0][10]) > 0, output
        else:
            assert all(row[7:11] == ["N/A"] * 4 for row in traffic_rows), output
        print("PASS sampled bandwidth and cumulative directional packets", flush=True)
    finally:
        traffic_stop.set()
        sender.join(timeout=2)
        traffic_client.close()

    port = server(socket.AF_INET, socket.SOCK_STREAM, "127.0.0.1")
    cmd("iptables", "-t", "nat", "-I", "OUTPUT", "-d", "127.0.0.9", "-p", "tcp", "--dport", "19090", "-j", "DNAT", "--to-destination", f"127.0.0.1:{port}")
    nat = socket.socket()
    nat.settimeout(2)
    nat.bind(("127.0.0.2", 0))
    nat.connect(("127.0.0.9", 19090))
    nat.sendall(b"nat")
    assert nat.recv(128)
    clients.append(nat)
    before = reports("-g", "dst,dport,proto", "-D", "19090")
    after = reports("-N", "-g", "dst,dport,proto", "-D", "19090")
    assert "127.0.0.9 | 19090 | tcp" in before, before
    assert f"127.0.0.1 | {port} | tcp" in after, after
    print("PASS DNAT grouping and original filter semantics", flush=True)

    port = server(socket.AF_INET, socket.SOCK_DGRAM, "127.0.0.1")
    cmd("iptables", "-t", "nat", "-I", "POSTROUTING", "-s", "127.0.0.2", "-p", "udp", "--dport", str(port), "-j", "SNAT", "--to-source", "127.0.0.3")
    snat = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    snat.settimeout(2)
    snat.bind(("127.0.0.2", 0))
    snat.sendto(b"snat", ("127.0.0.1", port))
    assert snat.recvfrom(128)[0] == b"snat"
    clients.append(snat)
    before = reports("-g", "src", "-D", str(port), "-s", "127.0.0.2")
    after = reports("-N", "-g", "src", "-D", str(port), "-s", "127.0.0.2")
    assert "127.0.0.2" in before and "127.0.0.3" in after, (before, after)
    print("PASS SNAT grouping", flush=True)

    udpport = server(socket.AF_INET, socket.SOCK_DGRAM, "127.0.0.1")
    monitor = sp.Popen([BIN, "-b", "-i", ".2", "-c", "12", "-p", "udp", "-D", str(udpport)], stdout=sp.PIPE, stderr=sp.PIPE, text=True)
    time.sleep(.65)
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.settimeout(2)
    u.sendto(b"new", ("127.0.0.1", udpport))
    assert u.recvfrom(128)[0] == b"new"
    clients.append(u)
    time.sleep(.4)
    cmd("conntrack", "-D", "-p", "udp", "--dport", str(udpport))
    output, error = monitor.communicate(timeout=8)
    assert monitor.returncode == 0, error
    rates = []
    for line in output.splitlines():
        if line.startswith("127.0.0.1"):
            cells = [cell.strip() for cell in line.split("|")]
            rates.append(cells[2:4])
    assert any(new != "N/A" and float(new) > 0 for new, _ in rates), output
    assert any(end != "N/A" and float(end) > 0 for _, end in rates), output
    print("PASS NEW and DESTROY events", flush=True)

    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 160, 0, 0))
    before = termios.tcgetattr(slave)
    env = dict(os.environ, TERM="xterm-256color", NO_COLOR="1")
    proc = sp.Popen([BIN, "-i", ".2"], stdin=slave, stdout=slave, stderr=slave, env=env)
    transcript = bytearray()
    screen = pyte.Screen(160, 40)
    stream = pyte.Stream(screen)
    decoder = codecs.getincrementaldecoder("utf-8")("replace")

    def drain(seconds):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if select.select([master], [], [], .05)[0]:
                chunk = os.read(master, 65536)
                transcript.extend(chunk)
                stream.feed(decoder.decode(chunk))

    drain(.5)
    os.write(master, b"0")
    drain(.4)
    visible = "\n".join(screen.display)
    assert "All connections | CT" in visible and "ENDPOINTS" in visible, visible
    os.write(master, b"0")
    drain(.4)
    assert "groups | sort" in "\n".join(screen.display), screen.display
    for key in [b"2", b"n", b"\r", b"\x1b", b"g\x15src,dst,proto\r", b"/127\r"]:
        os.write(master, key)
        drain(.4)
        if key == b"g\x15src,dst,proto\r":
            assert "src,dst,proto" in "\n".join(screen.display), screen.display
        if key == b"\r":
            visible = "\n".join(screen.display)
            assert "Original" in visible and "Reply" in visible, visible
            if open("/proc/sys/net/netfilter/nf_conntrack_acct").read().strip() == "1":
                packets = next(line for line in screen.display if line.startswith("\u2502Packets "))
                assert "N/A" not in packets.split("\u2502")[1], packets
            if open("/proc/sys/net/netfilter/nf_conntrack_timestamp").read().strip() == "1":
                assert "kernel timestamp" in visible, visible
    # Batched keys must rebuild between grouping and entering the selected row.
    os.write(master, b"6\r1")
    drain(.4)
    visible = "\n".join(screen.display)
    path = next(line.strip(" \u2502") for line in screen.display if "All >" in line)
    assert "dport=" in path and "src |" in visible, visible
    os.write(master, b"\r4")
    drain(.4)
    visible = "\n".join(screen.display)
    assert " > NAT:src=" in visible and "proto |" in visible, visible
    os.write(master, b"\x1b")
    drain(.4)
    visible = "\n".join(screen.display)
    assert path in visible and " > NAT:src=" not in visible, visible
    assert "src |" in visible, visible
    os.write(master, b"\x1b")
    drain(.4)
    visible = "\n".join(screen.display)
    assert "All >" not in visible and "dport |" in visible, visible
    os.write(master, b"h")
    drain(.3)
    assert "Help | h/Esc close" in "\n".join(screen.display)
    os.write(master, b"\x1b")
    drain(.3)
    assert "dport |" in "\n".join(screen.display)
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
    screen.resize(24, 80)
    proc.send_signal(signal.SIGWINCH)
    drain(.3)
    os.write(master, b"h")
    drain(.3)
    os.write(master, b"\x1b[6~")
    drain(.3)
    assert "Bandwidth" in "\n".join(screen.display), screen.display
    os.write(master, b"h")
    drain(.3)
    os.write(master, b"q")
    drain(.3)
    proc.wait(timeout=3)
    assert proc.returncode == 0
    assert termios.tcgetattr(slave) == before
    with open("/checks/tui-plain.ansi", "wb") as f:
        f.write(transcript)
    assert b"\x1b[?1049l" in transcript
    import re
    styles = re.findall(rb"\x1b\[([0-9;]*)m", transcript)
    assert not any(any(30 <= int(n) <= 38 or 40 <= int(n) <= 48 or 90 <= int(n) <= 107
                       for n in style.split(b";") if n) for style in styles), styles
    os.close(master)
    os.close(slave)
    print("PASS TUI hierarchical grouping/NAT/drilldown/search/resize/NO_COLOR/terminal restore", flush=True)

    master, slave = pty.openpty()
    before = termios.tcgetattr(slave)
    proc = sp.Popen([BIN], stdin=slave, stdout=slave, stderr=slave, env=env)
    drain(.3)
    proc.send_signal(signal.SIGTERM)
    drain(.3)
    proc.wait(timeout=3)
    assert proc.returncode == 0
    assert termios.tcgetattr(slave) == before
    os.close(master)
    os.close(slave)
    print("PASS SIGTERM restores terminal", flush=True)
finally:
    stop.set()
    for client in clients:
        client.close()
    for thread in threads:
        thread.join(timeout=3)
    for sock in sockets:
        sock.close()
