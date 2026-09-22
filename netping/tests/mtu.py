#!/usr/bin/env python3
"""MTU CLI/protocol checks and optional isolated routed-network validation.

python3 tests/mtu.py /path/to/netping [--skip-icmp]
sudo unshare -n python3 tests/mtu.py /path/to/netping --network
"""
import argparse
import contextlib
import os
from pathlib import Path
import select
import signal
import socket
import struct
import subprocess
import time

from retrans import server
from window import Responder


def run(binary, *args, code=0):
    p = subprocess.run([binary, *map(str, args)], capture_output=True, text=True, timeout=20)
    assert p.returncode == code, (p.returncode, p.stdout, p.stderr)
    assert '\x1b' not in p.stdout
    return p.stdout


def loopback(binary, skip_icmp):
    for v6 in (False, True):
        host, family, overhead = ('::1', '-6', 48) if v6 else ('127.0.0.1', '-4', 28)
        with server(binary, v6) as port:
            for size in (32, 1472, 8972):
                out = run(binary, '-M', '-u', family, '-p', port, '-l', size, '-i', '.002', host)
                assert f'Path MTU >= {size + overhead} bytes' in out, out
            with socket.socket(socket.AF_INET6 if v6 else socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(1)
                payload = bytearray(struct.pack('!4sBBHQQII', b'NPNG', 1, 0, 256, 123, 7, 4096, 0))
                payload.extend(bytes(4096 - len(payload)))
                sock.sendto(payload, (host, port))
                ack, _ = sock.recvfrom(65536)
                assert len(ack) == 32
                assert struct.unpack('!4sBBHQQII', ack) == (b'NPNG', 1, 1, 512, 123, 7, 32, 4096)
            out = run(binary, '-M', '-u', family, '-p', port, '-c', 1, host, code=1)
            assert 'probe count limit reached' in out and '1 probes' in out, out
            started = time.monotonic()
            out = run(binary, '-M', '-u', family, '-p', port, '-i', 86400, '-T', '.1', host, code=1)
            assert time.monotonic() - started < 1 and 'duration limit' in out, out
        if not skip_icmp:
            out = run(binary, '-M', family, '-l', 1472, '-i', '.002', host)
            assert f'Path MTU >= {1472 + overhead} bytes' in out, out
    with Responder() as old:
        out = run(binary, '-M', '-u', '-p', old.udp_port, '-W', '.05', '-i', '.002', old.host, code=1)
        assert 'no baseline reply' in out and 'Path MTU =' not in out, out
    with Responder(tcp='drop', udp='drop') as silent:
        p = subprocess.Popen([binary, '-M', '-u', '-p', str(silent.udp_port), '-W', '10', silent.host],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            assert select.select([p.stdout], [], [], 2)[0]
            p.send_signal(signal.SIGINT)
            out, err = p.communicate(timeout=2)
            assert p.returncode == 1 and 'interrupted' in out, (out, err)
        finally:
            if p.poll() is None:
                p.kill()
                p.wait()
    print('PASS: IPv4/IPv6 ceilings, 32-byte ACKs, legacy server, count/time limits and Ctrl+C', flush=True)


def command(pid, *args):
    prefix = ['nsenter', '-t', str(pid), '-n'] if pid else []
    return subprocess.run([*prefix, *map(str, args)], check=True, capture_output=True, text=True).stdout


@contextlib.contextmanager
def namespace():
    p = subprocess.Popen(['unshare', '-n', 'sleep', '120'])
    try:
        parent = os.readlink('/proc/self/ns/net')
        until = time.monotonic() + 2
        while os.readlink(f'/proc/{p.pid}/ns/net') == parent:
            assert time.monotonic() < until and p.poll() is None
            time.sleep(.005)
        yield p.pid
    finally:
        p.terminate()
        p.wait(timeout=2)


def network(binary):
    assert os.readlink('/proc/self/ns/net') != os.readlink('/proc/1/ns/net'), 'use unshare -n; never change host networking'
    with namespace() as router, namespace() as destination:
        command(None, 'ip', 'link', 'set', 'lo', 'up')
        for left, right in [('mtuc', 'mtur0'), ('mtur1', 'mtud')]:
            command(None, 'ip', 'link', 'add', left, 'type', 'veth', 'peer', 'name', right)
        command(None, 'ip', 'link', 'set', 'mtur0', 'netns', router)
        command(None, 'ip', 'link', 'set', 'mtur1', 'netns', router)
        command(None, 'ip', 'link', 'set', 'mtud', 'netns', destination)
        for pid, name, v4, v6, mtu in [
            (None, 'mtuc', '10.203.1.1', 'fd00:203:1::1', 9000),
            (router, 'mtur0', '10.203.1.2', 'fd00:203:1::2', 9000),
            (router, 'mtur1', '10.203.2.1', 'fd00:203:2::1', 1400),
            (destination, 'mtud', '10.203.2.2', 'fd00:203:2::2', 1400),
        ]:
            command(pid, 'ip', 'link', 'set', 'lo', 'up')
            command(pid, 'ip', 'link', 'set', name, 'mtu', mtu, 'up')
            command(pid, 'ip', 'addr', 'add', v4 + '/24', 'dev', name)
            command(pid, 'ip', '-6', 'addr', 'add', v6 + '/64', 'dev', name, 'nodad')
        command(router, 'sysctl', '-q', '-w', 'net.ipv4.ip_forward=1', 'net.ipv6.conf.all.forwarding=1')
        command(None, 'ip', 'route', 'add', '10.203.2.0/24', 'via', '10.203.1.2')
        command(destination, 'ip', 'route', 'add', '10.203.1.0/24', 'via', '10.203.2.1')
        command(None, 'ip', '-6', 'route', 'add', 'fd00:203:2::/64', 'via', 'fd00:203:1::2')
        command(destination, 'ip', '-6', 'route', 'add', 'fd00:203:1::/64', 'via', 'fd00:203:2::1')
        for family, host, firewall, icmp, icmp_type in [
            ('-4', '10.203.2.2', 'iptables', 'icmp', 'fragmentation-needed'),
            ('-6', 'fd00:203:2::2', 'ip6tables', 'ipv6-icmp', 'packet-too-big'),
        ]:
            server_process = subprocess.Popen(['nsenter', '-t', str(destination), '-n', binary, '-s', family],
                                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                assert select.select([server_process.stdout], [], [], 2)[0]
                assert 'UDP + TCP' in server_process.stdout.readline()
                common = ['-M', family, '-l', '1800', '-i', '.005', '-W', '.15', '-T', '15']
                for mode in ([], ['-u']):
                    command(None, 'sysctl', '-q', '-w', 'net.ipv4.ping_group_range=0 2147483647')
                    out = run(binary, *common, *mode, host)
                    assert 'Path MTU = 1400 bytes' in out and '(ICMP)' in out, out
                command(None, 'sysctl', '-q', '-w', 'net.ipv4.ping_group_range=1 0')
                out = run(binary, *common, host)
                assert 'Path MTU = 1400 bytes' in out, out
                # Suppress the router's Too Big errors, leaving small probes and ACKs intact.
                rule = ['OUTPUT', '-p', icmp, '--icmp-type' if family == '-4' else '--icmpv6-type', icmp_type, '-j', 'DROP']
                command(router, firewall, '-A', *rule)
                try:
                    for mode in ([], ['-u']):
                        out = run(binary, *common, *mode, host, code=1)
                        assert 'Largest confirmed IP size: 1400 bytes' in out, out
                        assert 'suspected size limit' in out and 'Path MTU =' not in out, out
                finally:
                    command(router, firewall, '-D', *rule)
                # Local interface limits must also be detected without inventing a remote error.
                command(None, 'ip', 'link', 'set', 'mtuc', 'mtu', 1300)
                try:
                    out = run(binary, *common, '-u', host)
                    assert 'Path MTU = 1300 bytes' in out and '(local)' in out, out
                finally:
                    command(None, 'ip', 'link', 'set', 'mtuc', 'mtu', 9000)
                print(f'PASS: {family} routed MTU=1400, ping/raw sockets, ICMP black hole, UDP ACKs, local MTU=1300', flush=True)
            finally:
                server_process.terminate()
                server_process.communicate(timeout=2)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--skip-icmp', action='store_true')
    parser.add_argument('--network', action='store_true')
    args = parser.parse_args()
    binary = str(args.binary.resolve())
    if args.network:
        network(binary)
    else:
        loopback(binary, args.skip_icmp)
