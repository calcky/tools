#!/usr/bin/env python3
"""MSS loopback/compatibility tests; --network requires an isolated net namespace."""
import argparse
import os
from pathlib import Path
import re
import select
import signal
import socket
import struct
import subprocess
import threading
import time

from mtu import command, namespace
from retrans import server
from window import Responder


def run(binary, *args, code=0):
    p = subprocess.run([binary, *map(str, args)], text=True, capture_output=True, timeout=5)
    assert p.returncode == code, (p.returncode, p.stdout, p.stderr)
    assert '\x1b' not in p.stdout
    return p.stdout


def value(out, name):
    m = re.search(r'^' + re.escape(name) + r'\s+(\d+)\s*$', out, re.M)
    return int(m[1]) if m else None


def captured(out):
    assert value(out, 'Local SYN MSS') and value(out, 'Peer SYN-ACK MSS'), out


def bad_reports(binary):
    for kind in ('session', 'sequence', 'length', 'disconnect', 'unavailable'):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen()
            listener.settimeout(3)
            errors = []
            def respond():
                try:
                    conn, _ = listener.accept()
                    with conn:
                        conn.settimeout(2)
                        data = bytearray()
                        while len(data) < 68:
                            part = conn.recv(68 - len(data))
                            assert part
                            data.extend(part)
                        if kind == 'disconnect':
                            return
                        data[9] = 1
                        data[36:44] = b'MSR1' + struct.pack('!I', 0 if kind == 'unavailable' else 1400)
                        if kind == 'session':
                            data[19] ^= 1
                        elif kind == 'sequence':
                            data[27] ^= 1
                        elif kind == 'length':
                            data[31] ^= 1
                        conn.sendall(data)
                except BaseException as error:
                    errors.append(error)
            worker = threading.Thread(target=respond, daemon=True)
            worker.start()
            out = run(binary, '-S', '-t', '-p', listener.getsockname()[1], '127.0.0.1', code=1)
            worker.join(timeout=3)
            assert not worker.is_alive() and not errors, errors
            assert value(out, 'Peer send MSS') is None and value(out, 'Local send MSS'), out
            if kind in ('session', 'sequence', 'length'):
                assert 'invalid MSS response' in out, out
    print('PASS: wrong session/sequence/length, disconnect and unavailable kernel data never become peer MSS', flush=True)


def loopback(binary, capture):
    for v6 in (False, True):
        host, family, af = ('::1', '-6', socket.AF_INET6) if v6 else ('127.0.0.1', '-4', socket.AF_INET)
        with socket.socket(af) as listener:
            listener.bind((host, 0))
            listener.listen()
            listener.settimeout(3)
            port = listener.getsockname()[1]
            p = subprocess.Popen([binary, '-S', family, '-p', str(port), host],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                conn, _ = listener.accept()
                with conn:
                    conn.settimeout(2)
                    assert conn.recv(1) == b'', 'ordinary MSS probes must not send application data'
                out, err = p.communicate(timeout=3)
                assert p.returncode == 0, (out, err)
                assert value(out, 'Local send MSS') and value(out, 'Peer send MSS') is None, out
                if capture:
                    captured(out)
                else:
                    assert 'capture unavailable' in out or value(out, 'Peer SYN-ACK MSS'), out
            finally:
                if p.poll() is None:
                    p.kill()
                    p.wait()
        with server(binary, v6) as port:
            out = run(binary, '-S', '-t', family, '-p', port, host)
            assert value(out, 'Local send MSS') and value(out, 'Peer send MSS'), out
            if capture:
                captured(out)
        # A framed response split into single bytes must retain its session and measured MSS.
        with socket.socket(af) as listener:
            listener.bind((host, 0))
            listener.listen()
            listener.settimeout(3)
            measured = []
            errors = []
            def respond():
                try:
                    conn, _ = listener.accept()
                    with conn:
                        conn.settimeout(2)
                        data = bytearray()
                        while len(data) < 68:
                            part = conn.recv(68 - len(data))
                            assert part
                            data.extend(part)
                        assert data[36:40] == b'MSQ1'
                        mss = struct.unpack_from('=I', conn.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 104), 16)[0]
                        measured.append(mss)
                        data[9] = 1
                        data[36:44] = b'MSR1' + struct.pack('!I', mss)
                        for byte in data:
                            conn.sendall(bytes([byte]))
                except BaseException as error:
                    errors.append(error)
            worker = threading.Thread(target=respond, daemon=True)
            worker.start()
            out = run(binary, '-S', '-t', family, '-p', listener.getsockname()[1], host)
            worker.join(timeout=3)
            assert not worker.is_alive() and not errors, errors
            assert value(out, 'Peer send MSS') == measured[0], (out, measured)
        print(f'PASS: {family} ordinary/no application data, paired MSS, exact TCP_INFO report, split frames', flush=True)
    with Responder() as old:
        out = run(binary, '-S', '-t', '-p', old.tcp_port, old.host, code=1)
        assert 'does not support MSS' in out and value(out, 'Peer send MSS') is None, out
    with socket.socket() as reserved:
        reserved.bind(('127.0.0.1', 0))
        out = run(binary, '-S', '-p', reserved.getsockname()[1], '127.0.0.1', code=1)
        assert 'Connection: failed' in out and value(out, 'Local send MSS') is None, out
    with Responder(tcp='drop') as silent:
        start = time.monotonic()
        out = run(binary, '-S', '-t', '-W', '.1', '-p', silent.tcp_port, silent.host, code=1)
        assert 'query failed: timed out' in out and time.monotonic() - start < 2, out
        p = subprocess.Popen([binary, '-S', '-t', '-W', '10', '-p', str(silent.tcp_port), silent.host],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            assert select.select([p.stdout], [], [], 2)[0]
            time.sleep(.05)
            p.send_signal(signal.SIGINT)
            out, err = p.communicate(timeout=2)
            assert p.returncode == 1 and 'interrupted' in out, (out, err)
        finally:
            if p.poll() is None:
                p.kill()
                p.wait()
    print('PASS: legacy server, refusal, query timeout, Ctrl+C and plain redirected output', flush=True)
    bad_reports(binary)


def network(binary):
    assert os.readlink('/proc/self/ns/net') != os.readlink('/proc/1/ns/net'), 'use unshare -n; never change host networking'
    with namespace() as peer:
        command(None, 'ip', 'link', 'set', 'lo', 'up')
        command(None, 'ip', 'link', 'add', 'mssc', 'type', 'veth', 'peer', 'name', 'mssp')
        command(None, 'ip', 'link', 'set', 'mssp', 'netns', peer)
        for pid, dev, v4, v6 in [(None, 'mssc', '10.204.1.1', 'fd00:204::1'), (peer, 'mssp', '10.204.1.2', 'fd00:204::2')]:
            command(pid, 'ip', 'link', 'set', dev, 'mtu', 1500, 'up')
            command(pid, 'ip', 'addr', 'add', v4 + '/24', 'dev', dev)
            command(pid, 'ip', '-6', 'addr', 'add', v6 + '/64', 'dev', dev, 'nodad')
            command(pid, 'sysctl', '-q', '-w', 'net.ipv4.tcp_timestamps=1')
        for family, host, firewall in [('-4', '10.204.1.2', 'iptables'), ('-6', 'fd00:204::2', 'ip6tables')]:
            server_process = subprocess.Popen(['nsenter', '-t', str(peer), '-n', binary, '-s', family],
                                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                assert select.select([server_process.stdout], [], [], 3)[0]
                assert 'UDP + TCP' in server_process.stdout.readline()
                command(None, firewall, '-t', 'mangle', '-A', 'OUTPUT', '-p', 'tcp', '--tcp-flags', 'SYN,RST', 'SYN', '-j', 'TCPMSS', '--set-mss', 1300)
                command(peer, firewall, '-t', 'mangle', '-A', 'OUTPUT', '-p', 'tcp', '--tcp-flags', 'SYN,RST', 'SYN', '-j', 'TCPMSS', '--set-mss', 1200)
                out = run(binary, '-S', '-t', family, host)
                assert value(out, 'Local SYN MSS') == 1300, out
                assert value(out, 'Peer SYN-ACK MSS') == 1200, out
                assert value(out, 'Local send MSS') == 1188, out
                assert value(out, 'Peer send MSS') == 1288, out
                # Root without CAP_NET_RAW still obtains actual send MSS from both endpoints.
                p = subprocess.run(['setpriv', '--bounding-set=-net_raw', binary, '-S', '-t', family, host],
                                   text=True, capture_output=True, timeout=4)
                assert p.returncode == 0 and 'capture unavailable' in p.stdout, (p.stdout, p.stderr)
                assert value(p.stdout, 'Local send MSS') == 1188 and value(p.stdout, 'Peer send MSS') == 1288, p.stdout
                command(peer, firewall, '-A', 'INPUT', '-p', 'tcp', '--dport', 11111, '--syn', '-j', 'DROP')
                out = run(binary, '-S', family, '-W', '.1', host, code=1)
                assert 'Connection: failed (timed out)' in out, out
                assert value(out, 'Peer SYN-ACK MSS') is None and value(out, 'Local send MSS') is None, out
                print(f'PASS: {family} SYN/SYN-ACK clamp 1300/1200, actual send MSS 1188/1288, no-CAP_NET_RAW fallback', flush=True)
            finally:
                server_process.terminate()
                server_process.communicate(timeout=2)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--capture', action='store_true')
    parser.add_argument('--network', action='store_true')
    args = parser.parse_args()
    binary = str(args.binary.resolve())
    if args.network:
        network(binary)
    else:
        loopback(binary, args.capture)
