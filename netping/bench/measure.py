#!/usr/bin/env python3
"""Measure idle server CPU and bounded client/server RSS during loopback tests."""
import argparse
import os
import re
from pathlib import Path
import select
import signal
import socket
import subprocess
import tempfile
import time

p = argparse.ArgumentParser()
p.add_argument('binary', type=Path)
p.add_argument('--seconds', type=int, default=20)
args = p.parse_args()
binary = str(args.binary.resolve())
ticks = os.sysconf('SC_CLK_TCK')


def usage(pid):
    fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / ticks, int(fields[21]) * os.sysconf('SC_PAGE_SIZE') // 1024


with socket.socket() as s:
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
server = subprocess.Popen([binary, '-s', '-p', str(port)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
try:
    assert select.select([server.stdout], [], [], 3)[0]
    assert 'UDP + TCP' in server.stdout.readline()
    before, _ = usage(server.pid)
    start = time.monotonic()
    time.sleep(2)
    after, rss = usage(server.pid)
    idle = (after-before)/(time.monotonic()-start)*100
    print(f'idle server: CPU={idle:.2f}% of one core, RSS={rss} KiB', flush=True)
    assert idle < 5, idle
    for mode in ['-u', '-t']:
        with tempfile.TemporaryFile(mode='w+') as log:
            client = subprocess.Popen([binary, mode, '-b', '-r', '100', '-T', str(args.seconds), '-p', str(port), '127.0.0.1'], stdout=log, stderr=subprocess.PIPE, text=True)
            try:
                samples = []
                server_start, _ = usage(server.pid)
                start = time.monotonic()
                while client.poll() is None:
                    samples.append((time.monotonic()-start, usage(client.pid), usage(server.pid)))
                    time.sleep(.5)
                _, err = client.communicate(timeout=2)
                assert client.returncode == 0, err
                steady = [s for s in samples if s[0] >= 3] or samples
                client_rss = [s[1][1] for s in steady]
                server_rss = [s[2][1] for s in steady]
                elapsed = time.monotonic()-start
                cpu = samples[-1][1][0]/elapsed*100
                server_cpu = (samples[-1][2][0]-server_start)/elapsed*100
                print(f'{mode} 100 PPS, {elapsed:.1f}s: client CPU={cpu:.2f}%, server CPU={server_cpu:.2f}%, client RSS={min(client_rss)}..{max(client_rss)} KiB, server RSS={min(server_rss)}..{max(server_rss)} KiB', flush=True)
                assert max(client_rss)-min(client_rss) < 8192
                assert max(server_rss)-min(server_rss) < 8192
                log.seek(0)
                summary = log.read()
                counts = dict(re.findall(r'\b(Timeout|Failed|Pending)\s+(\d+)', summary))
                assert counts == {'Timeout': '0', 'Failed': '0', 'Pending': '0'}, summary
            finally:
                if client.poll() is None:
                    client.send_signal(signal.SIGINT)
                    client.communicate(timeout=3)
finally:
    if server.poll() is None:
        server.send_signal(signal.SIGINT)
    _, err = server.communicate(timeout=3)
    assert server.returncode == 0, err
