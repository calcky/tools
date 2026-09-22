#!/usr/bin/env python3
"""Loopback CLI and fault-injection checks. Starts only temporary test listeners."""
import argparse
import concurrent.futures
import contextlib
import heapq
from pathlib import Path
import re
import select
import signal
import socket
import struct
import subprocess
import threading
import time

parser = argparse.ArgumentParser()
parser.add_argument('binary', type=Path)
parser.add_argument('--skip-icmp', action='store_true', help='For hosts without ICMP socket permission')
args = parser.parse_args()
binary = str(args.binary.resolve())


def run(*argv, code=0, timeout=8):
    p = subprocess.run([binary, *map(str, argv)], capture_output=True, text=True, timeout=timeout)
    assert p.returncode == code, (argv, p.returncode, p.stdout, p.stderr)
    assert '\x1b' not in p.stdout
    return p.stdout


def counters(out):
    return {k.lower(): int(v) for k, v in re.findall(r'\b(Sent|Received|Timeout|Failed|Pending|Late|Duplicate|Reordered|Invalid|Limited|Skipped)\s+(\d+)', out)}


def port(family=socket.AF_INET):
    host = '::1' if family == socket.AF_INET6 else '127.0.0.1'
    with socket.socket(family, socket.SOCK_STREAM) as s:
        s.bind((host, 0))
        return s.getsockname()[1]


@contextlib.contextmanager
def server(v6=False):
    pnum = port(socket.AF_INET6 if v6 else socket.AF_INET)
    p = subprocess.Popen([binary, '-s', '-p', str(pnum), '-6' if v6 else '-4'],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        assert select.select([p.stdout], [], [], 3)[0], 'server readiness timeout'
        assert 'UDP + TCP' in p.stdout.readline(), p.stderr.read()
        yield pnum
    finally:
        if p.poll() is None:
            p.send_signal(signal.SIGINT)
        _, err = p.communicate(timeout=3)
        assert p.returncode == 0, err


def message(seq, reply=False, length=64, session=1234):
    return struct.pack('!4sBBHQQII', b'NPNG', 1, int(reply), 0, session, seq, length, 0) + bytes(length - 32)


def recv_exact(s, size):
    result = b''
    while len(result) < size:
        data = s.recv(size-len(result))
        assert data, (size, len(result))
        result += data
    return result


for v6 in (False, True):
    host = '::1' if v6 else '127.0.0.1'
    family = '-6' if v6 else '-4'
    with server(v6) as pnum:
        for mode in ('-u', '-t', '-C'):
            output = run(mode, family, '-p', pnum, '-c', 4, '-i', '.01', host)
            c = counters(output)
            assert c['sent'] == c['received'] == 4 and c['pending'] == c['timeout'] == 0, output
            assert ('connect=' if mode == '-C' else 'rtt=') in output
            output = run(mode, family, '-b', '-T', '.15', '-r', 100, '-p', pnum, host)
            c = counters(output)
            assert c['received'] > 1 and c['received'] == c['sent'], output
            labels = ('TX/s', 'RX/s', 'TX-kB/s', 'RX-kB/s', 'P50', 'P95', 'P99')
            if mode != '-C':
                labels += ('Payload TX/RX',)
            assert all(label in output for label in labels)
            output = run(mode, family, '-b', '-f', '-c', 20, '-T', 2, '-p', pnum, host)
            assert counters(output)['received'] == 20, output
        if not args.skip_icmp:
            output = run(family, '-c', 4, '-i', '.01', host)
            assert counters(output)['received'] == 4, output
            output = run(family, '-b', '-f', '-c', 20, '-T', 2, host)
            assert counters(output)['received'] == 20, output
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            outputs = list(pool.map(lambda mode: run(mode, family, '-p', pnum, '-c', 10, '-i', '.005', host), ['-u', '-t'] * 4))
            assert all(counters(out)['received'] == 10 for out in outputs)
    print(f'PASS: {family} ' + ('UDP/TCP/connect (ICMP explicitly skipped)' if args.skip_icmp else 'ICMP/UDP/TCP/connect') + ', ping/bench/flood, concurrent clients', flush=True)

# The real server must handle fragmentation, coalescing, invalid traffic, half-close,
# and another UDP peer without confusing their sessions.
with server() as pnum:
    with socket.create_connection(('127.0.0.1', pnum), timeout=2) as s:
        frames = b''.join(struct.pack('!I', 64) + message(n) for n in range(1, 4))
        for chunk in (frames[:1], frames[1:7], frames[7:68], frames[68:]):
            s.sendall(chunk)
            time.sleep(.003)
        s.shutdown(socket.SHUT_WR)
        for n in range(1, 4):
            assert recv_exact(s, 4) == struct.pack('!I', 64)
            assert recv_exact(s, 64) == message(n, True)
    with socket.create_connection(('127.0.0.1', pnum), timeout=2) as s:
        s.sendall(struct.pack('!I', 0xffffffff))
        assert s.recv(1) == b''
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(.1)
        for invalid in (b'bad', message(1, True), message(0), message(1, session=0)):
            s.sendto(invalid, ('127.0.0.1', pnum))
            try:
                s.recvfrom(65536)
                raise AssertionError('invalid request was echoed')
            except socket.timeout:
                pass
        s.sendto(message(1), ('127.0.0.1', pnum))
        assert s.recvfrom(65536)[0] == message(1, True)
    output = run('-t', '-p', pnum, '-l', 65507, '-b', '-r', 200, '-c', 50, '127.0.0.1')
    assert counters(output)['received'] == 50
print('PASS: TCP stream framing, half-close, large payloads, invalid message rejection', flush=True)


@contextlib.contextmanager
def udp_responder(faults=False):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('127.0.0.1', 0))
    s.setblocking(False)
    stopped = threading.Event()
    errors = []

    def worker():
        scheduled = []
        serial = 0
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as wrong_peer:
                while not stopped.is_set():
                    now = time.monotonic()
                    while scheduled and scheduled[0][0] <= now:
                        _, _, data, peer = heapq.heappop(scheduled)
                        s.sendto(data, peer)
                    ready, _, _ = select.select([s], [], [], .002)
                    if not ready:
                        continue
                    data, peer = s.recvfrom(65536)
                    if not faults:
                        continue
                    seq = struct.unpack('!Q', data[16:24])[0]
                    response = bytearray(data)
                    response[5] = 1
                    if seq == 1:
                        continue
                    if seq == 5:
                        invalid = bytearray(response)
                        invalid[8] ^= 1
                        s.sendto(invalid, peer)
                        wrong_peer.sendto(response, peer)
                    delay = .04 if seq == 2 else .14 if seq == 4 else 0
                    serial += 1
                    heapq.heappush(scheduled, (now + delay, serial, bytes(response), peer))
                    if seq == 3:
                        serial += 1
                        heapq.heappush(scheduled, (now + .005, serial, bytes(response), peer))
        except Exception as e:
            errors.append(e)
    t = threading.Thread(target=worker)
    t.start()
    try:
        yield s.getsockname()[1]
    finally:
        stopped.set()
        t.join(timeout=2)
        s.close()
        assert not errors, errors


with udp_responder(True) as pnum:
    output = run('-u', '-p', pnum, '-c', 14, '-i', '.02', '-W', '.10', '127.0.0.1')
    c = counters(output)
    assert (c['sent'], c['received'], c['timeout'], c['late'], c['duplicate'], c['invalid']) == (14, 12, 2, 1, 1, 1), output
    assert c['reordered'] == 1, output
    assert output.index('seq=3 rtt') < output.index('seq=2 rtt'), output
    assert re.search(r'^seq=2 rtt=.* ms reordered$', output, re.MULTILINE), output
with udp_responder() as pnum:
    started = time.monotonic()
    output = run('-u', '-p', pnum, '-c', 5, '-i', '.02', '-W', '.15', '127.0.0.1', code=1)
    assert time.monotonic() - started < .6, output
    c = counters(output)
    assert c['sent'] == c['timeout'] == 5 and c['received'] == c['pending'] == 0, output
    output = run('-u', '-p', pnum, '-b', '-f', '-c', 3, '-W', '.05', '127.0.0.1', code=1)
    assert counters(output)['timeout'] == 3, output
    p = subprocess.Popen([binary, '-u', '-p', str(pnum), '-i', '.01', '-W', '1', '127.0.0.1'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert select.select([p.stdout], [], [], 2)[0]
    header = p.stdout.readline()
    time.sleep(.04)
    p.send_signal(signal.SIGINT)
    out, _ = p.communicate(timeout=1)
    c = counters(out)
    assert c['pending'] > 0 and c['timeout'] == 0, header + out
print('PASS: losses, out-of-order, duplicates, late replies, wrong sessions/peers, nonblocking timeouts, Ctrl+C pending', flush=True)

pnum = port()
output = run('-C', '-p', pnum, '-c', 3, '-i', '.01', '127.0.0.1', code=1)
assert counters(output)['failed'] == 3 and 'Failure' in output and 'Loss' not in output
run('-t', '-p', pnum, '-W', '.1', '127.0.0.1', code=2)


def tcp_fault(stall, final_reply=False):
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen()
    done = threading.Event()

    def worker():
        s, _ = listener.accept()
        with s:
            if stall:
                done.wait(2)
            elif final_reply:
                size = struct.unpack('!I', recv_exact(s, 4))[0]
                data = bytearray(recv_exact(s, size))
                data[5] = 1
                s.sendall(struct.pack('!I', size) + data)
            else:
                s.recv(1024)
    thread = threading.Thread(target=worker)
    thread.start()
    try:
        out = run('-t', '-p', listener.getsockname()[1], '-c', 1 if final_reply else 5, '-i', '.01', '-W', '.1', '127.0.0.1', code=0 if final_reply else 1)
        c = counters(out)
        if final_reply:
            assert c['received'] == 1 and c['failed'] == 0, out
            return
        assert c['received'] == 0 and c['pending'] == 0, out
        assert c['timeout'] == 5 if stall else c['failed'] > 0, out
    finally:
        done.set()
        thread.join(timeout=2)
        listener.close()


tcp_fault(False)
tcp_fault(True)
tcp_fault(False, final_reply=True)
assert run('-v').strip() == 'netping 0.1.0'
assert '--' not in run('-h')
for invalid in (['--help'], ['-u', '-t', 'localhost'], ['-s', '-c', '1'], ['-i', 'NaN', 'localhost']):
    run(*invalid, code=2)
print('PASS: connection refusal, disconnect, TCP timeout, short CLI, clean redirected output', flush=True)
