"""Read-only CPU measurements in a real PTY; percentages are of one CPU core."""
import argparse
import errno
import fcntl
import json
import os
from pathlib import Path
import pty
import select
import struct
import subprocess
import termios
import time

parser = argparse.ArgumentParser()
parser.add_argument('root', type=Path)
parser.add_argument('--repeat', type=int, default=1)
parser.add_argument('--compare-softnet', action='store_true')
args = parser.parse_args()


def measure(command):
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 40, 120, 0, 0))
    env = {k: v for k, v in os.environ.items() if k != 'NO_COLOR'}
    env['TERM'] = 'xterm-256color'
    start = time.monotonic()
    proc = subprocess.Popen(command, stdin=slave, stdout=slave, stderr=slave, env=env)
    size = 0
    tail = b''
    try:
        while True:
            if select.select([master], [], [], 0.05)[0]:
                try:
                    data = os.read(master, 65536)
                except OSError as error:
                    if error.errno != errno.EIO:
                        raise
                    data = b''
                size += len(data)
                tail = (tail + data)[-2048:]
                if b'\x1b[6n' in tail:
                    os.write(master, b'\x1b[1;1R')
                    tail = tail.replace(b'\x1b[6n', b'')
            pid, status, usage = os.wait4(proc.pid, os.WNOHANG)
            if pid:
                proc.returncode = os.waitstatus_to_exitcode(status)
                break
            if time.monotonic() - start > 25:
                raise TimeoutError(command)
        wall = time.monotonic() - start
        assert proc.returncode == 0, tail.decode(errors='replace')
        cpu = usage.ru_utime + usage.ru_stime
        return dict(wall_s=round(wall, 3), cpu_s=round(cpu, 6),
                    cpu_percent=round(100 * cpu / wall, 3),
                    user_s=usage.ru_utime, system_s=usage.ru_stime,
                    voluntary_switches=usage.ru_nvcsw, max_rss_kb=usage.ru_maxrss,
                    output_bytes=size)
    finally:
        if proc.returncode is None:
            proc.kill()
            proc.wait()
        os.close(master)
        os.close(slave)


for repeat in range(args.repeat):
    for name, options in [('irqstat', ['-n']), ('irqtop', [])]:
        for interval, count in [('1', '10'), ('0.1', '50')]:
            for extra in ([[], ['-b']] if args.compare_softnet else [[]]):
                command = [str(args.root / name), *options, *extra, interval, count]
                result = measure(command)
                print(json.dumps(dict(command=command, repeat=repeat, **result)), flush=True)
