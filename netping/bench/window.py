#!/usr/bin/env python3
"""Measure window CPU/RSS with a PTY; optionally target an existing remote server."""
import argparse
import fcntl
import os
from pathlib import Path
import pty
import re
import select
import signal
import socket
import struct
import subprocess
import termios
import time


def usage(pid):
    fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
    return ((int(fields[11]) + int(fields[12])) / os.sysconf('SC_CLK_TCK'),
            int(fields[21]) * os.sysconf('SC_PAGE_SIZE') // 1024)


def controlling_terminal():
    os.setsid()
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('host', nargs='?', help='Existing remote netping server; otherwise start a loopback server')
    parser.add_argument('--port', type=int, default=11111)
    parser.add_argument('--seconds', type=int, default=60)
    parser.add_argument('--pps', type=int, default=20)
    parser.add_argument('--skip-icmp', action='store_true')
    args = parser.parse_args()
    binary = str(args.binary.resolve())
    server = None
    port = args.port
    master, slave = pty.openpty()
    attrs = termios.tcgetattr(slave)
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 24, 100, 0, 0))
    client = None
    try:
        if not args.host:
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0))
                port = sock.getsockname()[1]
            server = subprocess.Popen([binary, '-s', '-p', str(port)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            assert select.select([server.stdout], [], [], 3)[0]
            assert 'UDP + TCP' in server.stdout.readline()
            idle_start, _ = usage(server.pid)
            time.sleep(2)
            idle_end, _ = usage(server.pid)
            idle = (idle_end - idle_start) / 2 * 100
            print(f'idle server CPU: {idle:.2f}% of one core', flush=True)
            assert idle < 5
        argv = [binary, '-w', '-r', str(args.pps), '-T', str(args.seconds), '-p', str(port), args.host or '127.0.0.1']
        client = subprocess.Popen(argv, stdin=slave, stdout=slave, stderr=slave,
                                  env={**os.environ, 'TERM': 'xterm-256color'}, preexec_fn=controlling_terminal)
        started = time.monotonic()
        next_sample = started
        samples = []
        output = bytearray()
        while client.poll() is None:
            if select.select([master], [], [], .1)[0]:
                output.extend(os.read(master, 65536))
                del output[:-1048576]
            now = time.monotonic()
            if now >= next_sample:
                cpu, rss = usage(client.pid)
                if rss:
                    samples.append((now - started, cpu, rss))
                next_sample = now + 1
            assert now - started < args.seconds + 5, 'window failed to stop'
        while select.select([master], [], [], 0)[0]:
            output.extend(os.read(master, 65536))
        elapsed = time.monotonic() - started
        assert termios.tcgetattr(slave) == attrs, 'terminal settings not restored'
        text = output.decode(errors='replace')
        assert b'\x1b[?1049l' in output, 'alternate screen not restored'
        summary = text.split('\x1b[?1049l')[-1]
        stats = re.findall(r'--- (.+?) statistics.*?(?=netping \||\Z)', summary, re.S)
        assert len(stats) == 3, summary
        counters = re.findall(r'\b(Sent|Received|Timeout|Failed|Pending)\s+(\d+)', summary)
        assert len(counters) == 15, summary
        for index in range(3):
            counts = {key: int(value) for key, value in counters[index * 5:(index + 1) * 5]}
            if index == 0 and args.skip_icmp:
                continue
            assert counts['Received'] > 0 and counts['Pending'] == 0, summary
            assert counts['Sent'] == counts['Received'] + counts['Timeout'] + counts['Failed'], summary
            if not args.host:
                assert counts['Timeout'] == counts['Failed'] == 0, summary
        assert client.returncode == (1 if args.skip_icmp else 0), summary
        steady = [s for s in samples if s[0] >= 5] or samples
        rss = [s[2] for s in steady]
        cpu = samples[-1][1] / elapsed * 100
        print(f'window {args.pps} PPS/protocol, {elapsed:.1f}s: CPU={cpu:.2f}% of one core; steady RSS={min(rss)}..{max(rss)} KiB', flush=True)
        print(summary.strip(), flush=True)
        assert cpu < 5, cpu
        assert max(rss) - min(rss) < 8192, rss
    finally:
        if client is not None and client.poll() is None:
            client.send_signal(signal.SIGTERM)
            client.wait(timeout=3)
        if server is not None:
            if server.poll() is None:
                server.send_signal(signal.SIGINT)
            server.communicate(timeout=3)
        os.close(master)
        os.close(slave)


if __name__ == '__main__':
    main()
