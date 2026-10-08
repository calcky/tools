#!/usr/bin/env python3
"""Multi-session loopback, fault isolation and PTY checks."""
import argparse
import contextlib
import re
import select
import signal
import socket
import subprocess
import time
from collections import Counter
from pathlib import Path

from window import Pty, Responder, summaries


def run(binary, *argv, code=0):
    result = subprocess.run([binary, *map(str, argv)], capture_output=True,
                            text=True, timeout=8)
    assert result.returncode == code, (argv, result.stdout, result.stderr)
    assert '\x1b' not in result.stdout
    return result.stdout


def rows(output):
    return [line.split() for line in output.splitlines()
            if re.match(r'^\s+\d+\s+\S+\s+\d+\s+\d+\s+\d+\.\d+', line)]


def counts(output):
    return {name.lower(): int(value) for name, value in re.findall(
        r'\b(Sent|Received|Timeout|Failed|Pending|Late|Duplicate|Reordered|Invalid|Skipped)\s+(\d+)', output)}


@contextlib.contextmanager
def paired_server(binary, v6):
    family = socket.AF_INET6 if v6 else socket.AF_INET
    host = '::1' if v6 else '127.0.0.1'
    with socket.socket(family, socket.SOCK_STREAM) as listener:
        listener.bind((host, 0))
        port = listener.getsockname()[1]
    proc = subprocess.Popen([binary, '-s', '-p', str(port), '-6' if v6 else '-4'],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        assert select.select([proc.stdout], [], [], 3)[0], 'server startup timeout'
        assert 'UDP + TCP' in proc.stdout.readline()
        yield host, port
    finally:
        proc.send_signal(signal.SIGINT)
        _, error = proc.communicate(timeout=3)
        assert proc.returncode == 0, error


def loopback(binary, skip_icmp):
    for v6 in (False, True):
        with paired_server(binary, v6) as (host, port):
            family = '-6' if v6 else '-4'
            for mode in ('-u', '-t', '-C', *(() if skip_icmp else ('',))):
                argv = [mode, '-p', port] if mode else []
                started = time.monotonic()
                out = run(binary, *argv, family, '-j', 4, '-c', 6, '-r', 20, host)
                assert out.count('netping |') == 1, out
                assert counts(out)['sent'] == counts(out)['received'] == 24, out
                assert len(rows(out)) == 4, out
                assert all(row[2:4] == ['6', '6'] for row in rows(out)), out
                assert time.monotonic() - started < 1, 'sessions ran serially'
                if mode != '-C':
                    assert len({row[1] for row in rows(out)}) == 4, out
                assert set(re.findall(r'session=(\d+) seq=', out)) == {'1', '2', '3', '4'}, out
                out = run(binary, *argv, family, '-j', 3, '-b', '-f', '-c', 8, '-T', 2, host)
                assert counts(out)['sent'] == counts(out)['received'] == 24, out
                out = run(binary, *argv, family, '-j', 3, '-b', '-r', 20, '-T', .3, host)
                c = counts(out)
                assert 12 <= c['sent'] <= 21 and c['received'] == c['sent'], out
            out = run(binary, '-t', family, '-j', 1, '-p', port, '-c', 2, '-i', .01, host)
            assert 'session=' not in out and 'Session details' not in out
    print('PASS: IPv4/IPv6 UDP/TCP/connect' + (' (ICMP skipped)' if skip_icmp else '/ICMP') + ', distinct endpoints, per-session count/rate/flood')


def fault_isolation(binary):
    with Responder(udp='replay', tcp='replay') as server:
        for mode, lane in [('-u', 'UDP'), ('-t', 'TCP')]:
            out = run(binary, mode, '-j', 3, '-p', server.udp_port, '-c', 6, '-i', .02, server.host)
            c = counts(out)
            assert c['received'] == 18 and c['invalid'] == 2, out
            requests = server.requests(lane)
            assert len({event[2] for event in requests}) == 3
            assert all(n == 6 for n in Counter(event[2] for event in requests).values())
    with Responder(udp='faults') as server:
        out = run(binary, '-u', '-j', 3, '-p', server.udp_port, '-c', 8, '-i', .05, '-W', .1, server.host)
        c = counts(out)
        assert c['received'] == 15 and c['timeout'] == 9 and c['duplicate'] == 3 and c['late'] == 3, out
        assert all(row[2:7] == ['8', '5', '37.50', '3', '0'] for row in rows(out)), out
    with Responder(udp='reorder') as server:
        out = run(binary, '-u', '-j', 3, '-p', server.udp_port, '-c', 6, '-i', .03, '-W', .2, server.host)
        assert counts(out)['received'] == 18 and counts(out)['reordered'] == 3, out
    for mode, fault in [('-u', 'first-drop'), ('-t', 'first-close')]:
        with Responder(**({'udp': fault} if mode == '-u' else {'tcp': fault})) as server:
            out = run(binary, mode, '-j', 3, '-p', server.udp_port, '-c', 6, '-i', .02, '-W', .1, server.host, code=1)
            assert sorted(int(row[3]) for row in rows(out)) == [0, 6, 6], out
    with Responder(udp='delay') as server:
        proc = subprocess.Popen([binary, '-u', '-j', '3', '-p', str(server.udp_port),
                                 '-i', '.1', server.host], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
        try:
            time.sleep(.15)
            proc.send_signal(signal.SIGINT)
            out, error = proc.communicate(timeout=3)
            assert proc.returncode == 1, (out, error)
            c = counts(out)
            assert c['pending'] == c['sent'] > 0 and c['timeout'] == 0, out
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
        out = run(binary, '-t', '-j', 3, '-p', port, '-c', 1, '127.0.0.1', code=1)
        assert len(rows(out)) == 3 and counts(out)['sent'] == 0, out
        assert out.count('connection setup failures: 1') == 3, out
    print('PASS: session replay rejection, independent loss/duplicate/late counts, Ctrl+C pending, connection failures')


def window_sessions(binary, skip_icmp):
    with Responder() as server:
        with Pty(binary, server.argv('-j', 4, '-r', 10, '-W', .2), env={'NO_COLOR': '1'}) as pty:
            pty.resize(80, 24)
            pty.until(lambda: 'Sessions:4' in pty.screen.text)
            pty.key(b'js')
            pty.until(lambda: 'UDP sessions' in pty.screen.text and 'P95:' in pty.screen.text)
            pty.key(b'jjj')
            pty.until(lambda: '> S4' in pty.screen.text)
            before = len(server.requests('UDP'))
            pty.key(b' ')
            pty.until(lambda: 'PAUSED' in pty.screen.text)
            pty.hold(.3)
            paused = len(server.requests('UDP'))
            pty.hold(.2)
            assert len(server.requests('UDP')) == paused
            assert paused >= before
            pty.key(b' ')
            pty.until(lambda: len(server.requests('UDP')) > paused)
            old = {e[2] for e in server.requests('UDP')}
            pty.key(b'r')
            pty.until(lambda: len({e[2] for e in server.requests('UDP')} - old) == 4)
            pty.key(b's')
            pty.until(lambda: 'UDP sessions' not in pty.screen.text and 'ICMP | ms' in pty.screen.text)
            pty.key(b'q')
            assert pty.finish() == (1 if skip_icmp else 0)
            assert bytes(pty.raw).count(b'Session details') == 3
    with Responder() as server:
        with Pty(binary, server.argv('-j', 3, '-c', 5, '-i', .05)) as pty:
            pty.finish()
            result = summaries(pty, skip_icmp)
            assert result['UDP']['sent'] == result['UDP']['received'] == 15
            assert result['TCP echo']['sent'] + result['TCP echo']['skipped'] == 15
            assert len(rows(bytes(pty.raw).decode(errors='replace'))) == 9
    with Responder(v6=True, separate=True) as server:
        with Pty(binary, server.argv('-C', '-j', 3, '-c', 5, '-i', .05)) as pty:
            pty.finish()
            result = summaries(pty, skip_icmp, connect=True)
            assert result['UDP']['received'] == 15
            assert result['TCP connect']['received'] == 15
    print('PASS: protocol/session views, navigation, pause/resume/reset, automatic drain, terminal restoration')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--skip-icmp', action='store_true')
    args = parser.parse_args()
    binary = str(args.binary.resolve())
    loopback(binary, args.skip_icmp)
    fault_isolation(binary)
    window_sessions(binary, args.skip_icmp)


if __name__ == '__main__':
    main()
