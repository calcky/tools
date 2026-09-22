#!/usr/bin/env python3
"""TCP_INFO, optional peer telemetry, and real loss in an isolated network namespace.

python3 tests/retrans.py /path/to/netping
sudo unshare -n python3 tests/retrans.py /path/to/netping --loss
"""
import argparse
import contextlib
import os
from pathlib import Path
import re
import select
import socket
import subprocess
import time

from window import Pty, Responder, detail, panel_text


def totals(output):
    match = re.search(r'TCP retrans Tx/Rx = (\d+|-)/(\d+|-) segments', output)
    assert match, output
    return tuple(None if n == '-' else int(n) for n in match.groups())


@contextlib.contextmanager
def server(binary, v6=False):
    with socket.socket(socket.AF_INET6 if v6 else socket.AF_INET) as sock:
        sock.bind(('::1' if v6 else '127.0.0.1', 0))
        port = sock.getsockname()[1]
    process = subprocess.Popen([binary, '-s', '-p', str(port), '-6' if v6 else '-4'],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        assert select.select([process.stdout], [], [], 3)[0], 'server readiness timeout'
        assert 'UDP + TCP' in process.stdout.readline()
        yield port
    finally:
        process.terminate()
        _, error = process.communicate(timeout=3)
        assert process.returncode == 0, error


def run(binary, *args):
    result = subprocess.run([binary, *map(str, args)], text=True, capture_output=True, timeout=15)
    assert result.returncode == 0, (result.returncode, result.stdout, result.stderr)
    return result.stdout


def compatibility(binary):
    for v6 in (False, True):
        host, family = ('::1', '-6') if v6 else ('127.0.0.1', '-4')
        with server(binary, v6) as port:
            for size in (32, 39, 40, 64):
                output = run(binary, '-t', family, '-l', size, '-p', port, '-c', 4, '-i', '.02', host)
                assert totals(output) == (0, 0 if size >= 40 else None), output
            output = run(binary, '-C', family, '-p', port, '-c', 4, '-i', '.02', host)
            assert totals(output) == (0, None), output
    with Responder() as legacy:
        output = run(binary, '-t', '-p', legacy.tcp_port, '-c', 4, '-i', '.02', legacy.host)
        assert totals(output) == (0, None), output
    print('PASS: IPv4/IPv6, short payloads, legacy server and TCP connect', flush=True)


def window(binary):
    with server(binary) as port:
        with Pty(binary, ['-w', '-p', port, '-i', '.05', '127.0.0.1']) as pty:
            pty.until(lambda: re.search(r'\bRx\s+0\s+0\.00', panel_text(pty, 'TCP echo')))
            assert re.search(r'\bTx\s+0\s+0\.00', panel_text(pty, 'TCP echo'))
            pty.resize(80, 24)
            pty.until(lambda: 'Rx:0 (0.00/s)' in panel_text(pty, 'TCP echo'))
            assert 'Tx:0 (0.00/s)' in panel_text(pty, 'TCP echo')
            pty.key(b'q')
            pty.finish()
            assert totals(pty.raw.decode(errors='replace')) == (0, 0)
    print('PASS: live counts and rates at 120x30 and 80x24, exit summary', flush=True)


def alerts(binary):
    def title(pty):
        for line in pty.screen.text.splitlines():
            if 'TCP echo | ms' in line:
                return line.split('TCP echo | ms', 1)[1]
        return ''

    for no_color in (False, True):
        with Responder(tcp='retrans') as peer:
            with Pty(binary, peer.argv('-i', '.05', '-W', '.2'),
                     env={'NO_COLOR': '1'} if no_color else {}) as pty:
                pty.until(lambda: 'RETRANS' in title(pty))
                assert detail(pty, 'TCP echo', 'Timeout') == 0
                assert detail(pty, 'TCP echo', 'Failed') == 0
                pty.resize(80, 24)
                pty.until(lambda: 'RETRANS' in title(pty) and 'Rx:' in pty.screen.text
                          and 'q quit' in pty.screen.text)
                peer.command(pty, 'mode', 'TCP', 'normal')
                pty.until(lambda: 'Ready' in title(pty), timeout=3)
                assert re.search(r'Rx:[1-9]\d* \(0.00/s\)', panel_text(pty, 'TCP echo'))
                peer.command(pty, 'mode', 'TCP', 'drop')
                pty.until(lambda: 'TIMEOUT' in title(pty))
                peer.command(pty, 'mode', 'TCP', 'normal')
                pty.until(lambda: 'Ready' in title(pty))
                peer.command(pty, 'down')
                pty.until(lambda: 'DISCONNECTED' in title(pty))
                pty.hold(1.2)
                assert 'DISCONNECTED' in title(pty)
                udp_before = len(peer.requests('UDP'))
                peer.command(pty, 'up')
                pty.until(lambda: 'Ready' in title(pty), timeout=3)
                assert len(peer.requests('UDP')) > udp_before
                assert detail(pty, 'TCP echo', 'Timeout') > 0
                pty.key(b'q')
                pty.finish()
                if no_color:
                    colors = set(range(30, 39)) | set(range(40, 49)) | set(range(90, 98)) | set(range(100, 108))
                    for match in re.finditer(rb'\x1b\[([0-9;:]*)m', pty.raw):
                        params = {int(n or 0) for n in re.split(rb'[;:]', match[1])}
                        assert not colors.intersection(params), match[0]
    print('PASS: RETRANS with successful replies, TIMEOUT, DISCONNECTED, recovery and NO_COLOR', flush=True)


def kernel_retrans():
    lines = Path('/proc/net/snmp').read_text().splitlines()
    for header, values in zip(lines, lines[1:]):
        if header.startswith('Tcp:') and values.startswith('Tcp:'):
            return dict(zip(header.split()[1:], map(int, values.split()[1:])))['RetransSegs']
    raise AssertionError('Tcp RetransSegs not found')


def real_loss(binary):
    assert os.readlink('/proc/self/ns/net') != os.readlink('/proc/1/ns/net'), 'use unshare -n; never alter the host network'
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    with server(binary) as port:
        try:
            subprocess.run(['tc', 'qdisc', 'add', 'dev', 'lo', 'root', 'netem', 'loss', '10%'], check=True)
            before = kernel_retrans()
            output = run(binary, '-t', '-b', '-r', 100, '-T', 5, '-W', 5,
                         '-l', 512, '-p', port, '127.0.0.1')
            tx, rx = totals(output)
            actual = kernel_retrans() - before
            assert tx is not None and rx is not None and tx > 0 and rx > 0, output
            assert actual >= tx + rx, (actual, tx, rx, output)
            print(f'PASS: injected data loss, Tx={tx}, Rx={rx}, kernel retransmissions={actual}', flush=True)
        finally:
            subprocess.run(['tc', 'qdisc', 'del', 'dev', 'lo', 'root'], check=True)
        process = None
        try:
            subprocess.run(['tc', 'qdisc', 'add', 'dev', 'lo', 'root', 'netem', 'loss', '100%'], check=True)
            process = subprocess.Popen([binary, '-C', '-c', '1', '-W', '4', '-p', str(port), '127.0.0.1'],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            assert select.select([process.stdout], [], [], 2)[0]
            header = process.stdout.readline()
            time.sleep(.3)
            subprocess.run(['tc', 'qdisc', 'change', 'dev', 'lo', 'root', 'netem', 'loss', '0%'], check=True)
            output, error = process.communicate(timeout=6)
            output = header + output
            assert process.returncode == 0, (output, error)
            tx, rx = totals(output)
            assert tx is not None and tx > 0 and rx is None, output
            print(f'PASS: SYN loss in connect mode, Tx={tx}, Rx=unavailable', flush=True)
        finally:
            subprocess.run(['tc', 'qdisc', 'del', 'dev', 'lo', 'root'], check=True)
            if process is not None and process.poll() is None:
                process.terminate()
                process.communicate(timeout=3)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--loss', action='store_true')
    args = parser.parse_args()
    binary = str(args.binary.resolve())
    if args.loss:
        real_loss(binary)
    else:
        compatibility(binary)
        window(binary)
        alerts(binary)


if __name__ == '__main__':
    main()
