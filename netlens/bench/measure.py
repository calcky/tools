"""Run a real terminal monitor for a bounded CPU/interaction smoke measurement."""
import argparse
import fcntl
import json
import os
import pty
import resource
import select
import struct
import subprocess
import termios
import time

parser = argparse.ArgumentParser()
parser.add_argument("binary")
parser.add_argument("--seconds", type=float, default=16)
parser.add_argument("--section", default="overview")
parser.add_argument("--trace", default=None)
parser.add_argument("--capture", default=None)
parser.add_argument("--keys", default="[]", help="JSON list of [seconds, text] terminal inputs")
parser.add_argument("--width", type=int, default=160)
parser.add_argument("--height", type=int, default=40)
parser.add_argument("--profile", default=None)
parser.add_argument("--warmup", type=float, default=5)
parser.add_argument("--interval", default="1", help="Sampling interval in seconds")
args = parser.parse_args()
master, slave = pty.openpty()
fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", args.height, args.width, 0, 0))
module = {"netdevice": "interface", "nic": "interface"}.get(args.section, args.section)
command = [args.binary, module, "-d", args.interval]
if args.trace:
    command = ["strace", "-f", "-qq", "-e", "trace=execve", "-o", args.trace] + command
if args.profile:
    command = [os.path.join(os.path.dirname(args.binary), "perf"), "record", "-q", "-e", "cpu-clock", "-F", "199", "--call-graph", "dwarf,8192", "-o", args.profile, "--"] + command
env = dict(os.environ, TERM="xterm-256color")
start_usage = resource.getrusage(resource.RUSAGE_CHILDREN)
started = time.monotonic()
process = subprocess.Popen(command, stdin=slave, stdout=slave, stderr=slave, env=env)
os.close(slave)
output = bytearray()
quit_sent = False
timed_out = False
keys = iter(json.loads(args.keys))
next_key = next(keys, None)
cpu_points = []
rss_points = []
last_sample = started
clock_ticks = os.sysconf("SC_CLK_TCK")
while process.poll() is None:
    elapsed = time.monotonic() - started
    if time.monotonic() - last_sample >= 1 and not args.profile and not args.trace:
        try:
            with open(f"/proc/{process.pid}/stat") as stat_file:
                fields = stat_file.read().rsplit(") ", 1)[1].split()
            own_user, own_system, child_user, child_system = (
                int(fields[index]) / clock_ticks for index in (11, 12, 13, 14)
            )
            own = own_user + own_system
            children = child_user + child_system
            cpu_points.append((elapsed, own, children, own_user, own_system,
                               child_user, child_system))
            rss_points.append(int(fields[21]) * os.sysconf("SC_PAGE_SIZE"))
        except (OSError, ValueError):
            pass
        last_sample = time.monotonic()
    if next_key is not None and elapsed >= next_key[0]:
        os.write(master, next_key[1].encode())
        next_key = next(keys, None)
    if elapsed >= args.seconds and not quit_sent:
        os.write(master, b"q")
        quit_sent = True
    if elapsed > args.seconds + 15:
        process.kill()
        timed_out = True
        break
    if select.select([master], [], [], 0.05)[0]:
        try:
            output.extend(os.read(master, 65536))
        except OSError:
            break
process.wait(timeout=15)
os.close(master)
usage = resource.getrusage(resource.RUSAGE_CHILDREN)
wall = time.monotonic() - started
cpu = usage.ru_utime + usage.ru_stime - start_usage.ru_utime - start_usage.ru_stime
if args.capture:
    with open(args.capture, "wb") as capture:
        capture.write(output)
print(json.dumps({"binary": args.binary, "section": args.section,
                  "exit_code": process.returncode, "wall_s": round(wall, 3),
                  "cpu_s_including_children": round(cpu, 4),
                  "cpu_percent_one_core": round(100 * cpu / wall, 2),
                  "terminal_bytes": len(output)}))
steady = [point for point in cpu_points if point[0] >= args.warmup]
if len(steady) >= 2:
    first, last = steady[0], steady[-1]
    duration = last[0] - first[0]
    bins = [100 * ((b[1] + b[2]) - (a[1] + a[2])) / (b[0] - a[0])
            for a, b in zip(steady, steady[1:])]
    print(json.dumps({"steady_s": round(duration, 2),
                      "parent_cpu_percent": round(100 * (last[1] - first[1]) / duration, 2),
                      "children_cpu_percent": round(100 * (last[2] - first[2]) / duration, 2),
                      "parent_user_percent": round(100 * (last[3] - first[3]) / duration, 2),
                      "parent_system_percent": round(100 * (last[4] - first[4]) / duration, 2),
                      "children_user_percent": round(100 * (last[5] - first[5]) / duration, 2),
                      "children_system_percent": round(100 * (last[6] - first[6]) / duration, 2),
                      "peak_rss_mib": round(max(rss_points, default=0) / (1024 * 1024), 2),
                      "one_second_cpu_percent": [round(value, 1) for value in bins]}))
if process.returncode != 0:
    if timed_out:
        print("monitor failed to quit within the grace period")
    print(output[-2000:].decode(errors="replace"))
    raise SystemExit(1)
