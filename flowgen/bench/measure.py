#!/usr/bin/env python3
"""Opt-in loopback load checks. Keep logs and recordings for reproducible analysis."""
import argparse
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import time


def usage(pid):
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    cpu = (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")
    rss = int(fields[21]) * os.sysconf("SC_PAGE_SIZE") // 1024
    return cpu, rss


def stop(process):
    if process.poll() is None:
        process.send_signal(signal.SIGINT)
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--sessions", type=int, default=1000)
    parser.add_argument("--seconds", type=float, default=20)
    parser.add_argument("--warmup", type=float, default=10)
    parser.add_argument("--pps", type=float, default=1)
    parser.add_argument("--turnover", type=float, default=0)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--protocol", choices=["tcp", "udp"], default="udp")
    args = parser.parse_args()
    binary = str(args.binary.resolve())
    root = Path(tempfile.mkdtemp(prefix="flowgen-bench-"))
    print(f"artifacts: {root}", flush=True)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = str(sock.getsockname()[1])
    with (root / "server.log").open("w") as server_log, (root / "client.log").open("w") as client_log:
        server = subprocess.Popen([binary, "-s",
                                   "-p", port, "-w", str(args.workers), "-o", str(root / "server")],
                                  stdout=server_log, stderr=subprocess.STDOUT)
        client = None
        try:
            deadline = time.monotonic() + 10
            while "server" not in (root / "server.log").read_text().lower():
                if server.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError((root / "server.log").read_text())
                time.sleep(.05)
            before, _ = usage(server.pid)
            time.sleep(1)
            after, rss = usage(server.pid)
            print(f"idle server CPU={(after-before)*100:.2f}% RSS={rss} KiB", flush=True)
            # Entire 127/8 is routed locally on Linux; no interface/sysctl changes.
            needed = args.sessions + int(args.turnover * args.seconds) + 1024
            sources = max(1, (needed + 44999) // 45000)
            if sources > 250:
                raise ValueError("benchmark source pool too large")
            command = [binary, "-t" if args.protocol == "tcp" else "-u", "-p", port,
                       "-c", str(args.sessions), "-a", str(args.warmup), "-T", str(args.seconds),
                       "-r", str(args.pps), "-U", str(args.turnover), "-w", str(args.workers),
                       "-P", "20000-64999", "-o", str(root / "client")]
            for index in range(sources):
                command += ["-B", f"127.{1 + os.getpid() % 240}.{1 + index}.2"]
            command.append("127.0.0.1")
            client = subprocess.Popen(command, stdout=client_log, stderr=subprocess.STDOUT)
            started = time.monotonic()
            server_before, _ = usage(server.pid)
            samples = []
            with (root / "resources.csv").open("w") as data:
                data.write("elapsed,client_cpu_s,client_rss_kib,server_cpu_s,server_rss_kib\n")
                while client.poll() is None:
                    elapsed = time.monotonic() - started
                    if elapsed > args.warmup + args.seconds + 300:
                        raise TimeoutError("load or analysis did not complete")
                    try:
                        cc, cr = usage(client.pid)
                        sc, sr = usage(server.pid)
                    except FileNotFoundError:
                        break
                    samples.append((elapsed, cc, cr, sc - server_before, sr))
                    data.write(f"{elapsed:.3f},{cc:.3f},{cr},{sc-server_before:.3f},{sr}\n")
                    data.flush()
                    time.sleep(1)
            result = client.wait(timeout=10)
            load = [s for s in samples if args.warmup + 2 <= s[0] <= args.warmup + args.seconds]
            if load:
                elapsed = max(1, load[-1][0] - load[0][0])
                print(f"load client/server CPU={(load[-1][1]-load[0][1])/elapsed*100:.2f}%/"
                      f"{(load[-1][3]-load[0][3])/elapsed*100:.2f}%", flush=True)
                print(f"load RSS client={min(s[2] for s in load)}..{max(s[2] for s in load)} KiB "
                      f"server={min(s[4] for s in load)}..{max(s[4] for s in load)} KiB", flush=True)
            print("\n".join((root / "client.log").read_text().splitlines()[-18:]), flush=True)
            if result != 0:
                raise RuntimeError(f"client exited {result}; see {root / 'client.log'}")
        finally:
            if client is not None:
                stop(client)
            stop(server)


if __name__ == "__main__":
    main()
