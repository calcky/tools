"""Reconstruct Ratatui differential output with pyte; inspect cells, not ANSI spelling."""
import fcntl
from collections import Counter
import os
from pathlib import Path
import pty
import re
import select
import signal
import struct
import subprocess
import sys
import termios
import time

import pyte
from pyte.graphics import FG_BG_256

root = Path(sys.argv[1]).resolve()


class Session:
    def __init__(self, options=(), interval='0.2', term='xterm', no_color=False):
        self.master, self.slave = pty.openpty()
        self.screen = pyte.Screen(80, 24)
        self.screen.write_process_input = lambda text: os.write(self.master, text.encode())
        self.stream = pyte.ByteStream(self.screen)
        self.raw = bytearray()
        self.resize(24, 80)
        self.original = termios.tcgetattr(self.slave)
        env = {k: v for k, v in os.environ.items() if k != 'NO_COLOR'}
        env['TERM'] = term
        if no_color:
            env['NO_COLOR'] = '1'
        self.proc = subprocess.Popen([str(root / 'irqtop'), *options, interval],
            stdin=self.slave, stdout=self.slave, stderr=self.slave,
            env=env)

    def resize(self, rows, cols):
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack('HHHH', rows, cols, 0, 0))
        self.screen.resize(lines=rows, columns=cols)

    def read(self, seconds=0.15):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if select.select([self.master], [], [], 0.02)[0]:
                chunk = os.read(self.master, 65536)
                self.raw.extend(chunk)
                self.stream.feed(chunk)

    def wait(self, predicate, timeout=4):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            self.read(0.05)
            if predicate():
                return
            assert self.proc.poll() is None, bytes(self.raw).decode(errors='replace')
        raise AssertionError('\n'.join(self.screen.display))

    def contains(self, text):
        return any(text in line for line in self.screen.display)

    def content_lines(self):
        return [line[1:-1] if line.startswith('\u2502') and line.endswith('\u2502') else line
                for line in self.screen.display]

    def panel_focused(self, title):
        return any(title in line and line.startswith('\u250c') and self.screen.buffer[y][0].bold
                   for y, line in enumerate(self.screen.display))

    def send(self, keys):
        os.write(self.master, keys)

    def start_row(self):
        match = re.search(r'Rows (\d+)-', '\n'.join(self.screen.display))
        return int(match[1]) if match else 0

    def table(self, unit='rate/s'):
        lines = self.content_lines()
        assert lines[5].endswith(unit), lines[5]
        assert self.screen.buffer[5][1].bold
        assert self.screen.display[5][0] == self.screen.display[5][-1] == '\u2502'
        main = [(y, line) for y, line in enumerate(lines[6:-3], 6)
                if re.match(r'^\S+\s+all\s+', line)]
        assert main, '\n'.join(lines)
        for y, line in main:
            assert re.search(r'\d+(?:\.\d+)?$', line), line
            assert self.screen.buffer[y][1].bold, (y, line, self.screen.buffer[y][1])
            assert self.screen.buffer[y][self.screen.columns - 2].bold
            assert self.screen.display[y][0] == self.screen.display[y][-1] == '\u2502'
        for y, line in enumerate(lines[6:-3], 6):
            if line.startswith('  CPU'):
                cells = list(re.finditer(r'CPU\d+:\s+\d+(?:\.\d+)?', line))
                assert len(cells) == line.count('CPU'), line
                for match in cells:
                    label = self.screen.buffer[y][match.start() + 1]
                    value = self.screen.buffer[y][match.end()]
                    assert label.bold == value.bold
                    if label.fg != 'default':
                        assert label.fg in ({'green', FG_BG_256[2]} if label.bold else {'brightblack', FG_BG_256[8]}), label
                        assert value.fg in ({'green', FG_BG_256[2]} if value.bold else {'default'}), value
        return self.screen.buffer[main[0][0]][1].fg

    def close(self, sig=None, key=b'q'):
        if sig is None:
            self.send(key)
        else:
            self.proc.send_signal(sig)
        self.proc.wait(timeout=3)
        self.read()
        assert self.proc.returncode == 0, bytes(self.raw).decode(errors='replace')
        assert termios.tcgetattr(self.slave) == self.original, 'TTY not restored'
        assert b'\x1b[?1049l' in self.raw and b'\x1b[?25h' in self.raw

    def wait_table(self, unit='rate/s'):
        result = []

        def complete():
            try:
                result[:] = [self.table(unit)]
                return True
            except AssertionError:
                return False

        # A differential draw may arrive in several PTY reads after resizing.
        self.wait(complete)
        return result[0]

    def dispose(self):
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()
        os.close(self.master)
        os.close(self.slave)


s = Session(['-m', '0'])
try:
    s.wait(lambda: s.contains('Rows 1-'))
    hard_color = s.wait_table()
    assert s.contains('rate off')
    assert not s.contains('CPU columns') and not s.contains('filter')
    s.send(b'\x1b[6~')
    s.wait(lambda: s.start_row() > 1)
    page = s.start_row()
    s.send(b'\x1b[A')
    s.wait(lambda: 0 < s.start_row() < page)
    s.send(b'G')
    s.wait(lambda: s.contains('NET_RX') or s.contains('TIMER') or s.contains('SCHED'))
    assert s.wait_table() != hard_color
    s.send(b'g')
    s.wait(lambda: s.start_row() == 1)
    s.send(b'n')
    s.wait(lambda: s.contains('network hard'))
    s.send(b'n')
    s.read()
    assert s.contains('network hard') and s.start_row() == 1
    assert not s.contains('TIMER') and not s.contains('SCHED')
    s.send(b'a')
    s.wait(lambda: s.contains('all hard'))
    s.send(b'a')
    s.read()
    assert s.contains('all hard')
    for height, width in [(12, 60), (24, 120), (24, 80)]:
        s.resize(height, width)
        s.wait(lambda: s.content_lines()[5].endswith('rate/s'))
        s.wait_table()
    s.resize(6, 40)
    s.wait(lambda: s.contains('Terminal too small'))
    s.resize(24, 100)
    s.wait(lambda: s.content_lines()[5].endswith('rate/s'))
    s.wait_table()
    s.send(b'z')
    s.wait(lambda: s.contains('CPU rate > 200/s'))
    s.send(b'z')
    s.wait(lambda: s.contains('CPU rate > 0/s'))
    s.send(b's')
    s.read()
    s.wait_table()
    capture = os.environ.get('IRQSTAT_CAPTURE')
    if capture:
        Path(capture).write_text('\n'.join(s.screen.display) + '\n')
    s.close()
finally:
    s.dispose()

s = Session(['-n', '-m', '0'])
try:
    s.wait(lambda: s.contains('NET_RX') and s.contains('Rows 1-'))
    s.wait_table()
    s.send(b'a')
    s.wait(lambda: s.contains('all hard + all softirqs'))
    s.close(key=b'\x03')
finally:
    s.dispose()

interfaces = {path.name for path in Path('/sys/class/net').iterdir()} - {'lo'}
test_device = next((name for name in ['nic0', 'eth0'] if name in interfaces), sorted(interfaces)[0])
s = Session(['-i', test_device, '-m', '0'])
try:
    s.wait(lambda: s.contains(f'({test_device})') and s.contains('Rows 1-'))
    assert s.contains('network hard + NET_RX/NET_TX')
    s.send(b'a')
    s.wait(lambda: s.contains('all hard + all softirqs') and not s.contains(f'({test_device})'))
    s.send(b'n')
    s.wait(lambda: s.contains('network hard + NET_RX/NET_TX'))
    assert not s.contains(f'({test_device})')
    s.close()
finally:
    s.dispose()

s = Session(['-n', '-d', '-m', '0'])
try:
    s.wait(lambda: s.contains('Rows 1-'))
    s.wait_table('count')
    assert s.contains('rate off') and 'count' in s.screen.display[1]
    s.close()
finally:
    s.dispose()

for sig in [signal.SIGINT, signal.SIGTERM, signal.SIGHUP]:
    s = Session(['-a', '-m', '0'])
    try:
        s.wait(lambda: s.contains('Rows 1-'))
        s.close(sig=sig)
    finally:
        s.dispose()

for sig in [None, signal.SIGTERM]:
    s = Session(interval='30')
    try:
        s.wait(lambda: s.contains('sampling'))
        started = time.monotonic()
        s.close(sig=sig)
        assert time.monotonic() - started < 1.0, 'slow exit during long sample interval'
    finally:
        s.dispose()

s = Session(['-n', '-m', '0'], no_color=True)
try:
    s.wait(lambda: s.contains('Rows 1-'))
    assert s.wait_table() == 'default'
    s.close()
finally:
    s.dispose()

s = Session(['-n', '-b', '-m', '0'])
try:
    s.wait(lambda: s.contains('SOFTNET | host') and s.contains('processed/s')
           and s.contains('Tab softnet'))
    assert s.contains('Tab softnet')
    assert s.panel_focused('IRQ / SOFTIRQ') and not s.panel_focused('SOFTNET | host')
    for height, width in [(20, 55), (24, 80), (40, 120)]:
        s.resize(height, width)
        s.wait(lambda: s.contains('processed/s') and s.contains('backlog')
               and s.content_lines()[5].endswith('rate/s'))
        assert s.contains('SOFTNET | host')
        assert s.content_lines()[5].endswith('rate/s')
    s.send(b'\t')
    s.wait(lambda: s.panel_focused('SOFTNET | host') and s.contains('Tab IRQ'))
    assert not s.panel_focused('IRQ / SOFTIRQ')
    s.send(b'G')
    s.read()
    assert s.panel_focused('SOFTNET | host')
    assert any(line.startswith('all ') for line in s.content_lines())
    s.send(b'b')
    s.wait(lambda: not s.contains('SOFTNET'))
    s.send(b'b')
    s.wait(lambda: s.contains('SOFTNET | host') and s.contains('processed/s'))
    s.send(b'szn')
    s.read()
    assert s.contains('SOFTNET | host')
    capture = os.environ.get('IRQSTAT_SOFTNET_CAPTURE')
    if capture:
        Path(capture).write_text('\n'.join(s.screen.display) + '\n')
    s.close()
finally:
    s.dispose()

s = Session(['-b', '-d'], no_color=True)
try:
    s.wait(lambda: s.contains('SOFTNET | host') and s.contains('processed'))
    assert not s.contains('processed/s')
    assert all(cell.fg == 'default' for row in s.screen.buffer.values() for cell in row.values())
    assert s.panel_focused('IRQ / SOFTIRQ') and not s.panel_focused('SOFTNET | host')
    s.send(b'\t')
    s.wait(lambda: s.panel_focused('SOFTNET | host') and not s.panel_focused('IRQ / SOFTIRQ'))
    s.close(sig=signal.SIGTERM)
finally:
    s.dispose()

for term in ['xterm', 'dumb']:
    result = subprocess.run([str(root / 'irqtop'), '-n', '-m', '0', '0.1', '2'],
        capture_output=True, text=True, timeout=5, env={**os.environ, 'TERM': term})
    assert result.returncode == 0 and '\x1b' not in result.stdout
    assert result.stdout.count('irqtop |') == 1
    records = [line.split() for line in result.stdout.splitlines()
               if re.match(r'^\d{2}:\d{2}:\d{2}\s+\S+\s+(?:CPU\d+|all|-)\s+', line)]
    assert records and set(Counter(row[1] for row in records).values()) == {2}
    assert {row[1] for row in records if row[3] == 'softirq'} == {'NET_RX', 'NET_TX'}
    assert 'CPU all = row total' not in result.stdout
print('PASS: Ratatui frames/focus, cells/styles, inner right edge, CPU peaks, paging, resize, scope/filter/sort, redirects, q/Ctrl+C/signals restore')
