#!/usr/bin/env python3
"""Bounded, stdlib-only PTY window tests with isolated loopback responders.

Usage: python3 tests/window.py /path/to/netping [--skip-icmp]
--skip-icmp permits an unavailable ICMP lane; it never disables that lane.
No root privileges, external echo services, or imports from verify.py are used.
"""

import argparse
import codecs
import contextlib
import errno
import fcntl
import heapq
import multiprocessing
import os
from pathlib import Path
import re
import select
import signal
import socket
import struct
import subprocess
import sys
import termios
import time
import traceback


ENTER = b'\x1b[?1049h'
LEAVE = b'\x1b[?1049l'
CSI = re.compile(r'\x1b\[([0-?]*)([ -/]*)([@-~])')
COUNTERS = ('Sent', 'Received', 'Timeout', 'Failed', 'Pending', 'Late',
            'Duplicate', 'Reordered', 'Invalid', 'Limited', 'Skipped')


class Screen:
    """Small VT cursor/erase reader for assertions on ratatui's diff output."""

    def __init__(self, width, height):
        self.decoder = codecs.getincrementaldecoder('utf-8')('replace')
        self.pending = ''
        self.resize(width, height)

    def resize(self, width, height):
        self.width, self.height = width, height
        self.cells = [[' '] * width for _ in range(height)]
        self.x = self.y = 0

    def feed(self, data):
        text = self.pending + self.decoder.decode(data)
        self.pending = ''
        i = 0
        while i < len(text):
            ch = text[i]
            if ch == '\x1b':
                match = CSI.match(text, i)
                if match is None:
                    self.pending = text[i:]
                    break
                params, _, command = match.groups()
                if not params.startswith('?'):
                    values = [int(v or 0) for v in params.split(';') if ':' not in v]
                    n = (values[0] if values else 0) or 1
                    if command in ('H', 'f'):
                        self.y = n - 1
                        self.x = ((values[1] if len(values) > 1 else 1) or 1) - 1
                    elif command == 'G':
                        self.x = n - 1
                    elif command == 'd':
                        self.y = n - 1
                    elif command in 'ABCD':
                        self.y += (n if command == 'B' else -n if command == 'A' else 0)
                        self.x += (n if command == 'C' else -n if command == 'D' else 0)
                    elif command == 'J' and values[0] in (2, 3):
                        self.cells = [[' '] * self.width for _ in range(self.height)]
                    elif command == 'K' and 0 <= self.y < self.height:
                        start = 0 if values[0] in (1, 2) else self.x
                        end = self.x + 1 if values[0] == 1 else self.width
                        self.cells[self.y][start:end] = [' '] * (end - start)
                i = match.end()
                continue
            if ch == '\r':
                self.x = 0
            elif ch == '\n':
                self.y += 1
            elif ch >= ' ':
                if self.x >= self.width:
                    self.x = 0
                    self.y += 1
                if 0 <= self.y < self.height and 0 <= self.x < self.width:
                    self.cells[self.y][self.x] = ch
                self.x += 1
            i += 1

    @property
    def text(self):
        return '\n'.join(''.join(row).rstrip() for row in self.cells)


def controlling_tty():
    os.setsid()
    fcntl.ioctl(2, termios.TIOCSCTTY, 0)


class Pty:
    def __init__(self, binary, argv, *, env=None, stdin_tty=True, stdout_tty=True):
        self.master, self.slave = os.openpty()
        self.before = termios.tcgetattr(self.slave)
        self.screen = Screen(120, 30)
        self.raw = bytearray()
        self.proc = None
        self.started = time.monotonic()
        self.resize(120, 30)
        child_env = dict(os.environ, TERM='xterm-256color', LC_ALL='C.UTF-8')
        child_env.pop('NO_COLOR', None)
        child_env.update(env or {})
        try:
            self.proc = subprocess.Popen(
                [binary, *map(str, argv)], stdin=self.slave if stdin_tty else subprocess.DEVNULL,
                stdout=self.slave if stdout_tty else subprocess.PIPE, stderr=self.slave,
                env=child_env, preexec_fn=controlling_tty)
        except BaseException:
            os.close(self.master)
            os.close(self.slave)
            raise
        self.readers = [self.master]
        if self.proc.stdout is not None:
            self.readers.append(self.proc.stdout.fileno())

    def __enter__(self):
        return self

    def __exit__(self, kind, error, tb):
        if error is not None and hasattr(error, 'add_note'):
            error.add_note('Last PTY screen:\n' + self.screen.text +
                           '\nOutput tail: ' + repr(bytes(self.raw[-2200:])))
        try:
            if self.proc.poll() is None:
                self.proc.terminate()
                try:
                    self.finish(1)
                except AssertionError:
                    self.proc.kill()
                    self.proc.wait(timeout=2)
            self.drain(0)
        finally:
            # Compare restoration before this cleanup, which also repairs failed runs.
            termios.tcsetattr(self.slave, termios.TCSANOW, self.before)
            if self.proc.stdout is not None:
                self.proc.stdout.close()
            os.close(self.master)
            os.close(self.slave)

    def resize(self, width, height):
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack('HHHH', height, width, 0, 0))
        if (width, height) != (self.screen.width, self.screen.height):
            self.screen.resize(width, height)
        if self.proc is not None and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGWINCH)

    def drain(self, timeout=.02):
        for fd in select.select(self.readers, [], [], timeout)[0]:
            try:
                data = os.read(fd, 65536)
            except OSError as exc:
                if exc.errno != errno.EIO:
                    raise
                data = b''
            if data:
                self.raw.extend(data)
                if fd == self.master:
                    self.screen.feed(data)
            elif fd != self.master:
                self.readers.remove(fd)

    def until(self, predicate, timeout=3, message='condition was not reached'):
        deadline = time.monotonic() + timeout
        while True:
            self.drain(.02)
            if predicate():
                return
            assert self.proc.poll() is None, f'premature exit {self.proc.returncode}: {message}'
            assert time.monotonic() < deadline, message

    def hold(self, seconds):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            self.drain(min(.02, max(0, deadline - time.monotonic())))
            assert self.proc.poll() is None, 'window exited while it should still be active'

    def key(self, value):
        os.write(self.master, value)

    def finish(self, timeout=5):
        deadline = time.monotonic() + timeout
        while self.proc.poll() is None:
            self.drain(.02)
            assert time.monotonic() < deadline, 'window did not exit before timeout'
        while select.select(self.readers, [], [], 0)[0]:
            self.drain(0)
        self.proc.wait(timeout=1)
        self.elapsed = time.monotonic() - self.started
        assert termios.tcgetattr(self.slave) == self.before, 'terminal settings were not restored'
        return self.proc.returncode


def responder_worker(pipe, v6, separate, udp_mode, tcp_mode):
    """One process owns both listeners, fault timers, and all accepted sockets."""
    family = socket.AF_INET6 if v6 else socket.AF_INET
    host = '::1' if v6 else '127.0.0.1'
    udp = listener = None
    clients, scheduled, first, ordinals = {}, [], {}, {}
    modes = {'UDP': udp_mode, 'TCP': tcp_mode}
    serial = 0

    def listen(port):
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(64)
        sock.setblocking(False)
        return sock

    def request(lane, payload, target):
        nonlocal serial
        assert len(payload) >= 32 and payload[:6] == b'NPNG\x01\x00', repr(payload)
        session, seq, length = struct.unpack('!QQI', payload[8:28])
        assert length == len(payload) and session and seq
        now = time.monotonic()
        pipe.send(('request', lane, session, seq, length, now))
        response = payload[:5] + b'\x01' + payload[6:]
        original = first.setdefault(lane, (session, response))
        key = lane, session
        ordinals[key] = ordinals.get(key, 0) + 1
        ordinal = ordinals[key]
        mode = modes[lane]
        if lane == 'TCP' and mode == 'retrans' and payload[32:36] == b'RTQ1':
            response = response[:32] + b'RTR1' + struct.pack('!I', ordinal) + response[40:]

        def enqueue(data, delay=0):
            nonlocal serial
            serial += 1
            heapq.heappush(scheduled, (now + delay, serial, lane, target, data))

        if mode == 'drop':
            return
        if mode == 'replay' and session != original[0] and ordinal == 1:
            enqueue(original[1])
        if mode == 'faults':
            if ordinal == 1:
                return
            if ordinal == 3:
                enqueue(response, .025)
            enqueue(response, .20 if ordinal == 2 else .60 if ordinal == 4 else 0)
        else:
            enqueue(response, .45 if mode == 'delay' else 0)

    try:
        udp = socket.socket(family, socket.SOCK_DGRAM)
        udp.bind((host, 0))
        udp.setblocking(False)
        udp_port = udp.getsockname()[1]
        listener = listen(0 if separate else udp_port)
        tcp_port = listener.getsockname()[1]
        pipe.send(('ready', udp_port, tcp_port))
        while True:
            now = time.monotonic()
            while scheduled and scheduled[0][0] <= now:
                _, _, lane, target, payload = heapq.heappop(scheduled)
                if lane == 'UDP':
                    udp.sendto(payload, target)
                elif target in clients:
                    clients[target][1].extend(struct.pack('!I', len(payload)) + payload)
            readers = [pipe, udp, *clients]
            if listener is not None:
                readers.append(listener)
            writers = [sock for sock, (_, pending) in clients.items() if pending]
            readable, writable, _ = select.select(readers, writers, [], .005)
            if pipe in readable:
                command = pipe.recv()
                if command[0] == 'stop':
                    break
                if command[0] == 'down':
                    listener.close()
                    listener = None
                    for sock in clients:
                        sock.close()
                    clients.clear()
                elif command[0] == 'up':
                    listener = listen(tcp_port)
                elif command[0] == 'mode':
                    modes[command[1]] = command[2]
                pipe.send(('ack', command[0], time.monotonic()))
            for sock in readable:
                if sock is udp:
                    payload, peer = udp.recvfrom(65536)
                    request('UDP', payload, peer)
                elif sock is listener:
                    conn, _ = listener.accept()
                    conn.setblocking(False)
                    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    clients[conn] = [bytearray(), bytearray()]
                    pipe.send(('accept', time.monotonic()))
                elif sock in clients:
                    try:
                        data = sock.recv(65536)
                    except ConnectionResetError:
                        data = b''
                    if not data:
                        sock.close()
                        del clients[sock]
                        continue
                    incoming = clients[sock][0]
                    incoming.extend(data)
                    while len(incoming) >= 4:
                        size = struct.unpack('!I', incoming[:4])[0]
                        assert 32 <= size <= 65507, size
                        if len(incoming) < size + 4:
                            break
                        request('TCP', bytes(incoming[4:4 + size]), sock)
                        del incoming[:4 + size]
            for sock in writable:
                if sock in clients:
                    pending = clients[sock][1]
                    try:
                        count = sock.send(pending)
                        del pending[:count]
                    except (BrokenPipeError, ConnectionResetError):
                        sock.close()
                        del clients[sock]
    except BaseException:
        with contextlib.suppress(BrokenPipeError, EOFError):
            pipe.send(('error', traceback.format_exc()))
        raise
    finally:
        for sock in [udp, listener, *clients]:
            if sock is not None:
                sock.close()
        pipe.close()


class Responder:
    def __init__(self, *, v6=False, separate=False, udp='normal', tcp='normal'):
        self.v6, self.separate = v6, separate
        self.host = '::1' if v6 else '127.0.0.1'
        self.events = []
        ctx = multiprocessing.get_context('spawn')
        self.pipe, child = ctx.Pipe()
        self.proc = ctx.Process(target=responder_worker, args=(child, v6, separate, udp, tcp))
        self.proc.start()
        child.close()

    def __enter__(self):
        try:
            assert self.pipe.poll(3), 'responder readiness timeout'
            event = self.pipe.recv()
            assert event[0] == 'ready', event
            _, self.udp_port, self.tcp_port = event
            return self
        except BaseException:
            self.__exit__(*sys.exc_info())
            raise

    def __exit__(self, kind, error, tb):
        try:
            if self.proc.is_alive():
                with contextlib.suppress(BrokenPipeError, EOFError):
                    self.pipe.send(('stop',))
            deadline = time.monotonic() + 2
            while self.proc.is_alive() and time.monotonic() < deadline:
                self.pump()
                self.proc.join(.02)
        finally:
            if self.proc.is_alive():
                self.proc.terminate()
                self.proc.join(1)
            if self.proc.is_alive():
                self.proc.kill()
                self.proc.join(1)
            self.pipe.close()
        if error is None:
            assert self.proc.exitcode == 0, f'responder exit {self.proc.exitcode}'

    def pump(self):
        while self.pipe.poll():
            try:
                event = self.pipe.recv()
            except EOFError:
                break
            assert event[0] != 'error', event[1:]
            self.events.append(event)

    def requests(self, lane):
        self.pump()
        return [event for event in self.events if event[:2] == ('request', lane)]

    def command(self, pty, *command):
        before = len(self.events)
        self.pipe.send(command)
        def acknowledged():
            self.pump()
            return any(e[:2] == ('ack', command[0]) for e in self.events[before:])
        pty.until(acknowledged, message=f'responder did not acknowledge {command}')

    def argv(self, *extra):
        ports = ['-p', self.udp_port]
        if self.separate:
            ports += ['-P', self.tcp_port]
        return ['-w', '-6' if self.v6 else '-4', *ports, *extra, self.host]


def summaries(pty, skip_icmp, *, connect=False, drained=True):
    raw = bytes(pty.raw)
    assert ENTER in raw and LEAVE in raw, 'alternate screen was not entered/restored'
    restored = raw.rindex(LEAVE)
    assert b'\x1b[?25h' in raw[:restored], 'cursor was not shown before leaving the window'
    assert b' statistics | ' not in raw[:restored], 'summaries printed before terminal restoration'
    final = raw[restored + len(LEAVE):].decode('utf-8', 'replace').replace('\r', '')
    # Ratatui's own Drop can show the cursor again after the terminal guard.
    final = re.sub(r'^(?:\x1b\[\?25h)*', '', final)
    assert '\x1b' not in final, 'final text summaries contain terminal escapes'
    matches = list(re.finditer(r'^--- (ICMP|UDP|TCP echo|TCP connect) statistics \| ([0-9.]+) s ---$',
                               final, re.MULTILINE))
    expected = ['ICMP', 'UDP', 'TCP connect' if connect else 'TCP echo']
    assert [m[1] for m in matches] == expected, final
    result = {}
    for i, match in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(final)
        body = final[match.end():end]
        counters = {key.lower(): int(value) for key, value in
                    re.findall(r'\b(' + '|'.join(COUNTERS) + r')\s+(\d+)', body)}
        assert set(counters) == {key.lower() for key in COUNTERS}, body
        assert counters['sent'] == sum(counters[k] for k in ('received', 'timeout', 'failed', 'pending')), body
        if drained:
            assert counters['pending'] == 0, body
        label = 'connect' if match[1] == 'TCP connect' else 'rtt'
        latency = re.search(label + r' min/avg/max/mdev = (\S+) ms', body)
        percentiles = re.search(r'Percentiles P50/P95/P99 = (\S+) ms', body)
        assert latency and percentiles, body
        for values, length in ((latency[1], 4), (percentiles[1], 3)):
            numbers = values.split('/')
            assert len(numbers) == length, body
            if counters['received']:
                assert all(float(n) >= 0 for n in numbers), body
                assert float(numbers[0]) <= float(numbers[1]) <= float(numbers[2]), body
            else:
                assert numbers == ['-'] * length, body
        counters['body'] = body
        counters['elapsed'] = float(match[2])
        result[match[1]] = counters
    icmp = result['ICMP']
    if not icmp['received']:
        assert skip_icmp, 'ICMP had no success; use --skip-icmp only on hosts without ICMP permission'
        assert 'Unavailable' in icmp['body'] and icmp['sent'] == 0, icmp
        assert b'Unavailable' in raw[:restored], 'unavailable ICMP lane was not displayed'
    expected_code = 0 if all(row['received'] > 0 for row in result.values()) else 1
    assert pty.proc.returncode == expected_code, (pty.proc.returncode, expected_code, final)
    return result


def healthy(row, count=None):
    assert row['received'] == row['sent'] > 0, row
    assert all(row[k] == 0 for k in ('timeout', 'failed', 'pending', 'late', 'duplicate', 'reordered', 'invalid')), row
    if count is not None:
        assert row['sent'] == count, row


def panel_text(pty, protocol):
    lines = pty.screen.text.splitlines()
    title = protocol + ' | ms'
    for y, line in enumerate(lines):
        if title not in line:
            continue
        corners = [(match.start(), match.group()) for match in re.finditer('[\u250c\u251c\u2510\u2524]', line)]
        start = max(x for x, char in corners if x < line.index(title) and char in '\u250c\u251c')
        end = min(x for x, char in corners if x > line.index(title) and char in '\u2510\u2524')
        assert start >= 0 and end > start, line
        content = [line[start + 1:end]]
        for body in lines[y + 1:]:
            if body[start:start + 1] != '\u2502':
                break
            assert body[end:end + 1] == '\u2502', body
            content.append(body[start + 1:end])
        return '\n'.join(content)
    return ''


def detail(pty, protocol, label):
    match = re.search(r'\b' + re.escape(label) + r'[: ]\s*(\d+)\b', panel_text(pty, protocol))
    return int(match[1]) if match else None


def cli_rejections(binary, skip_icmp):
    for stdin_tty, stdout_tty in ((False, False), (False, True), (True, False)):
        with Pty(binary, ['-w', '-c', 1, '127.0.0.1'],
                 stdin_tty=stdin_tty, stdout_tty=stdout_tty) as pty:
            assert pty.finish(2) == 2
            assert b'TTY' in pty.raw and b'\x1b' not in pty.raw, bytes(pty.raw)
    for option in ('-u', '-t', '-s', '-b', '-f', None):
        argv = ['-w', *([option] if option else []), '-c', 1, '127.0.0.1']
        with Pty(binary, argv, env={'TERM': 'dumb'} if option is None else {}) as pty:
            assert pty.finish(2) == 2
            assert b'\x1b' not in pty.raw and b'netping:' in pty.raw, bytes(pty.raw)


def concurrent_modes(binary, skip_icmp):
    for v6 in (False, True):
        for connect in (False, True):
            # Echo covers -p's common default; connect also proves -P leaves UDP alone.
            with Responder(v6=v6, separate=connect) as server:
                extra = ['-C', '-r', 20] if connect else ['-i', '.05']
                with Pty(binary, server.argv(*extra, '-c', 8, '-W', '.4', '-l', 257)) as pty:
                    pty.finish()
                    rows = summaries(pty, skip_icmp, connect=connect)
                    healthy(rows['UDP'], 8)
                    tcp = rows['TCP connect' if connect else 'TCP echo']
                    healthy(tcp, 8 if connect else None)
                    assert 1 <= tcp['sent'] <= 8, tcp
                    assert tcp['sent'] + tcp['skipped'] + tcp['limited'] >= 8, tcp
                    if rows['ICMP']['received']:
                        healthy(rows['ICMP'], 8)
                    udp = server.requests('UDP')
                    tcp_requests = server.requests('TCP')
                    assert len(udp) == 8 and all(e[4] == 257 for e in udp), udp
                    if connect:
                        assert not tcp_requests, 'connect lane sent echo payloads'
                        accepts = [e[1] for e in server.events if e[0] == 'accept']
                        assert len(accepts) == 8, accepts
                    else:
                        assert len(tcp_requests) == tcp['sent'], tcp_requests
                        assert all(e[4] == 257 for e in tcp_requests)
                        assert udp[0][2] != tcp_requests[0][2], 'protocols shared a session'
                        accepts = [e[5] for e in tcp_requests]
                    assert accepts[0] < udp[-1][5] and udp[0][5] < accepts[-1], 'lanes ran serially'
                    assert pty.elapsed < 2, pty.elapsed


def isolated_faults(binary, skip_icmp):
    for lane in ('UDP', 'TCP'):
        with Responder(separate=True, **{lane.lower(): 'faults'}) as server:
            with Pty(binary, server.argv('-c', 16, '-i', '.06', '-W', '.45')) as pty:
                pty.finish()
                rows = summaries(pty, skip_icmp)
                bad = rows['UDP' if lane == 'UDP' else 'TCP echo']
                assert bad['sent'] == len(server.requests(lane)), bad
                assert bad['received'] == bad['sent'] - 2, bad
                assert (bad['timeout'], bad['late'], bad['duplicate'], bad['reordered']) == (2, 1, 1, 1), bad
                assert bad['failed'] == bad['invalid'] == 0, bad
                healthy(rows['TCP echo' if lane == 'UDP' else 'UDP'])
                if rows['ICMP']['received']:
                    healthy(rows['ICMP'], 16)


def count_drains_and_failure_exit(binary, skip_icmp):
    for lane in ('UDP', 'TCP'):
        with Responder(**{lane.lower(): 'drop'}) as server:
            with Pty(binary, server.argv('-c', 5, '-T', 3, '-i', '.07', '-W', '.35')) as pty:
                assert pty.finish() == 1
                rows = summaries(pty, skip_icmp)
                bad = rows['UDP' if lane == 'UDP' else 'TCP echo']
                assert bad['timeout'] == bad['sent'] > 0 and bad['received'] == 0, bad
                last = server.requests(lane)[-1][5]
                assert time.monotonic() - last >= .32, 'count stopped without draining pending requests'
                healthy(rows['TCP echo' if lane == 'UDP' else 'UDP'])
                assert pty.elapsed < 1.8, 'count did not win over duration'


def reconnect(binary, skip_icmp):
    with Responder(separate=True) as server:
        with Pty(binary, server.argv('-i', '.08', '-W', '.4', '-T', 4)) as pty:
            pty.until(lambda: len(server.requests('TCP')) >= 3)
            old_tcp = server.requests('TCP')
            server.command(pty, 'down')
            down = time.monotonic()
            udp_before = len(server.requests('UDP'))
            pty.hold(.45)
            assert len(server.requests('UDP')) >= udp_before + 3, 'TCP disconnect stalled UDP'
            server.command(pty, 'up')
            up = time.monotonic()
            pty.until(lambda: len(server.requests('TCP')) >= len(old_tcp) + 3, timeout=2.3,
                      message='TCP echo did not recover after listener restart')
            recovered = server.requests('TCP')[len(old_tcp):]
            assert recovered[0][5] >= down + .75, 'TCP retried before the one-second backoff'
            assert recovered[0][5] < up + 1.6, 'TCP reconnect exceeded its retry interval'
            pty.finish()
            rows = summaries(pty, skip_icmp)
            healthy(rows['UDP'])
            tcp = rows['TCP echo']
            assert tcp['received'] >= len(old_tcp) + 2 and tcp['skipped'] >= 3, tcp
            assert len({e[2] for e in server.requests('TCP')}) == 1, 'reconnect unexpectedly reset the session'


def pause_resume(binary, skip_icmp):
    with Responder(udp='delay') as server:
        with Pty(binary, server.argv('-i', '.12', '-W', 1)) as pty:
            pty.until(lambda: len(server.requests('UDP')) >= 2)
            pty.key(b'j ')
            pty.until(lambda: 'PAUSED' in pty.screen.text and 'UDP | ms' in pty.screen.text)
            assert detail(pty, 'UDP', 'Pending') > 0, 'test failed to pause with in-flight UDP'
            frozen = {lane: len(server.requests(lane)) for lane in ('UDP', 'TCP')}
            pty.hold(.8)
            assert frozen == {lane: len(server.requests(lane)) for lane in frozen}, 'pause kept sending'
            udp_counts = re.search(r'^[> ]*UDP\s+(\d+)\s+(\d+)', pty.screen.text, re.M)
            assert detail(pty, 'UDP', 'Pending') == 0 and int(udp_counts[2]) == frozen['UDP'], 'pause did not drain replies'
            resumed = time.monotonic()
            pty.key(b' ')
            pty.until(lambda: len(server.requests('UDP')) >= frozen['UDP'] + 5)
            for lane in ('UDP', 'TCP'):
                events = [e for e in server.requests(lane) if e[5] >= resumed]
                assert len(events) >= 3, events
                assert all(b[5] - a[5] >= .055 for a, b in zip(events, events[1:])), 'resume sent a catch-up burst'
            pty.key(b'q')
            pty.finish(1)
            rows = summaries(pty, skip_icmp, drained=False)
            assert rows['UDP']['pending'] > 0 and rows['UDP']['timeout'] == 0, rows['UDP']
            assert rows['UDP']['skipped'] == 0, 'paused time was charged as missed send slots'


def reset_sessions(binary, skip_icmp):
    with Responder(udp='drop', tcp='drop') as server:
        with Pty(binary, server.argv('-c', 10, '-i', '.10', '-W', '.8')) as pty:
            pty.until(lambda: min(len(server.requests('UDP')), len(server.requests('TCP'))) >= 3)
            old = {lane: server.requests(lane)[0][2] for lane in ('UDP', 'TCP')}
            for lane in old:
                server.command(pty, 'mode', lane, 'replay')
            pty.key(b'r')
            pty.finish(3)
            rows = summaries(pty, skip_icmp)
            new_ids = []
            for lane, name in (('UDP', 'UDP'), ('TCP', 'TCP echo')):
                fresh = [e for e in server.requests(lane) if e[2] != old[lane]]
                assert fresh and len({e[2] for e in fresh}) == 1, 'reset did not create a fresh session'
                new_ids.append(fresh[0][2])
                row = rows[name]
                assert row['sent'] == row['received'] == len(fresh), row
                assert row['sent'] <= 10 and (lane != 'UDP' or row['sent'] == 10), row
                assert row['timeout'] == row['failed'] == row['pending'] == 0, row
                assert row['invalid'] == 1 and row['duplicate'] == row['late'] == 0, row
                assert fresh[0][3] <= 2, 'reset retained the previous sequence counter'
            assert len(set(new_ids + list(old.values()))) == 4, 'reset reused protocol session IDs'
            if rows['ICMP']['received']:
                healthy(rows['ICMP'], 10)


def duration_includes_pause(binary, skip_icmp):
    with Responder(udp='drop') as server:
        with Pty(binary, server.argv('-c', 100, '-T', '.65', '-i', '.08', '-W', '.9')) as pty:
            pty.until(lambda: len(server.requests('UDP')) >= 2)
            pty.key(b' ')
            pty.until(lambda: 'PAUSED' in pty.screen.text)
            frozen = len(server.requests('UDP'))
            pty.finish(2)
            rows = summaries(pty, skip_icmp)
            assert len(server.requests('UDP')) == frozen < 100, 'duration resumed sending while paused'
            assert rows['UDP']['timeout'] == rows['UDP']['sent'] == frozen, rows['UDP']
            assert .85 <= rows['UDP']['elapsed'] < 1.8, 'duration excluded paused time or failed to drain'
            healthy(rows['TCP echo'])


def immediate_exit_and_restore(binary, skip_icmp):
    for action in (b'q', b'\x03', signal.SIGINT, signal.SIGTERM):
        with Responder(udp='drop') as server:
            with Pty(binary, server.argv('-i', '.1', '-W', 4)) as pty:
                pty.until(lambda: len(server.requests('UDP')) >= 2 and bool(server.requests('TCP')))
                start = time.monotonic()
                if isinstance(action, bytes):
                    pty.key(action)
                else:
                    pty.proc.send_signal(action)
                pty.finish(1)
                assert time.monotonic() - start < .8, f'{action!r} waited for request timeout'
                rows = summaries(pty, skip_icmp, drained=False)
                udp = rows['UDP']
                assert udp['pending'] == udp['sent'] > 0 and udp['timeout'] == 0, udp


def navigation_resize_no_color(binary, skip_icmp):
    with Responder(udp='drop') as server:
        with Pty(binary, server.argv('-i', '.1', '-W', '.2'), env={'NO_COLOR': '1'}) as pty:
            pty.until(lambda: '> ICMP | ms' in pty.screen.text)
            for key, title in ((b'j', 'UDP'), (b'\x1b[B', 'TCP echo'),
                               (b'k', 'UDP'), (b'\x1b[A', 'ICMP')):
                pty.key(key)
                pty.until(lambda title=title: '> ' + title + ' | ms' in pty.screen.text)
                for protocol in ('ICMP', 'UDP', 'TCP echo'):
                    assert 'P99:' in panel_text(pty, protocol), 'selection hid another protocol'
            before = len(server.requests('UDP'))
            pty.resize(32, 8)
            pty.until(lambda: 'too small' in pty.screen.text.lower())
            pty.hold(.3)
            assert len(server.requests('UDP')) >= before + 2, 'small terminal stalled the engine'
            pty.key(b'k')
            pty.hold(.3)
            pty.resize(80, 24)
            pty.until(lambda: '> TCP echo | ms' in pty.screen.text)
            assert 'too small' not in pty.screen.text.lower()
            for width, height in ((80, 24), (100, 38), (120, 24), (160, 40), (60, 33)):
                pty.resize(width, height)
                pty.hold(.4)
                for protocol in ('ICMP', 'UDP', 'TCP echo'):
                    content = panel_text(pty, protocol)
                    for label in ('Min:', 'Max:', 'Mdev:', 'P50:', 'P95:', 'P99:',
                                  'Pending:', 'Timeout:', 'Failed:', 'Reordered:',
                                  'Duplicate:', 'Late:', 'Invalid:', 'Limited:',
                                  'Skipped:', 'ConnFail:'):
                        assert label in content, (width, height, protocol, label, content)
                assert detail(pty, 'UDP', 'Timeout') > 0
                assert detail(pty, 'TCP echo', 'Timeout') == 0
            pty.key(b'j')
            pty.until(lambda: '> ICMP | ms' in pty.screen.text)
            pty.key(b'q')
            pty.finish(1)
            summaries(pty, skip_icmp, drained=False)
            colors = set(range(30, 39)) | set(range(40, 49)) | set(range(90, 98)) | set(range(100, 108))
            for match in re.finditer(rb'\x1b\[([0-9;:]*)m', bytes(pty.raw)):
                params = [int(n or 0) for n in re.split(rb'[;:]', match[1])]
                assert not colors.intersection(params), f'NO_COLOR emitted a color SGR: {match[0]!r}'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--skip-icmp', action='store_true',
                        help='Permit ICMP Unavailable with zero sends; still run and display ICMP')
    args = parser.parse_args()
    binary = str(args.binary.resolve())
    if not os.path.isfile(binary) or not os.access(binary, os.X_OK):
        parser.error(f'binary is missing or not executable: {binary}')
    tests = (cli_rejections, concurrent_modes, isolated_faults, count_drains_and_failure_exit,
             reconnect, pause_resume, reset_sessions, duration_includes_pause,
             immediate_exit_and_restore, navigation_resize_no_color)
    failures = []
    started = time.monotonic()
    for test in tests:
        before = time.monotonic()
        try:
            test(binary, args.skip_icmp)
        except Exception:
            failures.append(test.__name__)
            print(f'FAIL: {test.__name__}', flush=True)
            traceback.print_exc()
        else:
            print(f'PASS: {test.__name__} ({time.monotonic() - before:.2f}s)', flush=True)
    print(f'{len(tests) - len(failures)}/{len(tests)} groups passed in {time.monotonic() - started:.2f}s', flush=True)
    if failures:
        print('Failed groups: ' + ', '.join(failures), flush=True)
    return int(bool(failures))


if __name__ == '__main__':
    sys.exit(main())
