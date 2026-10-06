#!/usr/bin/env python3
"""Measure bounded UDP loads only within an owned routed namespace fixture."""

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import statistics
import subprocess
import tempfile
import time
import uuid


HERE = Path(__file__).resolve().parent
HZ = os.sysconf('SC_CLK_TCK')


def run(argv):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError(f'{argv}: {result.stdout}{result.stderr}')
    return result.stdout


def stop(process):
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGINT)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


def observer_pid(binary):
    for path in Path('/proc').glob('[0-9]*/exe'):
        try:
            if path.resolve() == binary:
                return int(path.parent.name)
        except OSError:
            pass
    raise RuntimeError('collector PID not found')


def process_sample(pid):
    directory = Path('/proc') / str(pid)
    fields = (directory / 'stat').read_text().rsplit(')', 1)[1].split()
    status = dict(line.split(':', 1) for line in (directory / 'status').read_text().splitlines())
    return {'ticks': int(fields[11]) + int(fields[12]),
            'rss_kib': int(status['VmRSS'].split()[0]),
            'hwm_kib': int(status['VmHWM'].split()[0])}


def host_busy():
    values = [int(x) for x in Path('/proc/stat').read_text().splitlines()[0].split()[1:9]]
    return sum(values) - values[3] - values[4]


def map_info(pid):
    ids = set()
    for path in (Path('/proc') / str(pid) / 'fdinfo').iterdir():
        match = re.search(r'^map_id:\s*(\d+)$', path.read_text(), re.MULTILINE)
        if match:
            ids.add(int(match[1]))
    return [json.loads(run(['bpftool', '-j', 'map', 'show', 'id', str(identifier)]))
            for identifier in sorted(ids)]


def trial(node_command, binary, directory, rate, seconds, observe, capacity=None):
    directory.mkdir()
    processes = []
    handles = []

    def start(target, filename, *argv):
        handle = (directory / filename).open('w')
        handles.append(handle)
        process = subprocess.Popen(node_command(target, *argv), stdout=handle,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        processes.append(process)
        return process

    try:
        collector = None
        pid = None
        deadline = time.monotonic() + 30
        while True:
            other_collectors = []
            for path in Path('/proc').glob('[0-9]*/exe'):
                try:
                    if path.resolve().name == 'skbtop':
                        other_collectors.append(path.parent.name)
                except OSError:
                    pass
            if not other_collectors:
                break
            if time.monotonic() > deadline:
                raise RuntimeError(f'baseline requires no other skbtop collectors: {other_collectors}')
            time.sleep(0.25)
        if observe:
            arguments = ['-i', 'eth0,eth1', '-d', '0.5', '-c', str(2 * (seconds + 5)),
                         '-T', str(seconds + 5), '-o', str(directory / 'capture')]
            if capacity:
                arguments += ['-m', str(capacity[0]), '-g', str(capacity[1])]
            collector = start('r1', 'collector.log', str(binary), *arguments)
            deadline = time.monotonic() + 30
            snapshots = directory / 'capture/snapshots.jsonl'
            while not snapshots.exists() or '"type":"snapshot"' not in snapshots.read_text():
                if collector.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError(f'collector startup failed: {directory / "collector.log"}')
                time.sleep(0.1)
            pid = observer_pid(binary)
            maps = map_info(pid)
            (directory / 'maps.json').write_text(json.dumps(maps, indent=2) + '\n')
        server = start('h2', 'server.json', 'iperf3', '-s', '-1', '-J')
        time.sleep(0.25)
        ping = start('h1', 'ping.log', 'ping', '-4', '-n', '-c', str(seconds * 20),
                     '-i', '0.05', '-w', str(seconds + 2), '198.51.100.2')
        before = process_sample(pid) if pid else None
        host_before = host_busy()
        started = time.monotonic()
        client = start('h1', 'client.json', 'iperf3', '-c', '198.51.100.2', '-u',
                       '-b', f'{rate}M', '-l', '512', '-t', str(seconds), '-J')
        peak_rss = before['rss_kib'] if before else 0
        peak_hwm = before['hwm_kib'] if before else 0
        deadline = started + seconds + 15
        while client.poll() is None:
            if time.monotonic() > deadline:
                raise RuntimeError('UDP client timed out')
            if pid:
                sample = process_sample(pid)
                peak_rss = max(peak_rss, sample['rss_kib'])
                peak_hwm = max(peak_hwm, sample['hwm_kib'])
            time.sleep(0.2)
        elapsed = time.monotonic() - started
        host_delta = host_busy() - host_before
        after = process_sample(pid) if pid else None
        if client.returncode or server.wait(timeout=10):
            raise RuntimeError('iperf3 failed; inspect client/server JSON')
        ping.wait(timeout=5)
        if collector and collector.wait(timeout=15):
            raise RuntimeError('collector failed after load')
        for handle in handles:
            handle.flush()
        iperf = json.loads((directory / 'client.json').read_text())
        if 'error' in iperf:
            raise RuntimeError(iperf['error'])
        receiver = iperf['end']['sum_received']
        rtts = sorted(float(x) for x in re.findall(r'time=(\d+(?:\.\d+)?) ms',
                                                   (directory / 'ping.log').read_text()))
        result = {'recording': str(directory), 'offered_mbps': rate, 'observer': observe,
                  'received_mbps': receiver['bits_per_second'] / 1e6,
                  'lost_percent': receiver['lost_percent'], 'packets': receiver['packets'],
                  'ping_samples': len(rtts),
                  'rtt_p99_ms': rtts[math.ceil(len(rtts) * 0.99) - 1] if rtts else None,
                  'endpoint_cpu_percent': iperf['end']['cpu_utilization_percent'],
                  'shared_host_busy_core_percent': host_delta / HZ / elapsed * 100}
        if observe:
            summary = json.loads((directory / 'capture/summary.json').read_text())
            result.update(collector_cpu_core_percent=(after['ticks'] - before['ticks']) / HZ / elapsed * 100,
                          collector_peak_rss_kib=peak_rss, collector_hwm_kib=peak_hwm,
                          kernel_maps_reported_memlock_bytes=sum(m['bytes_memlock'] for m in maps),
                          health=summary['health'], complete=summary['complete'],
                          reconciliation=summary['reconciliation'],
                          paths=[{'key': p['row']['key'], 'total': p['row']['total'],
                                  'pending': p['row']['pending'],
                                  'total_p99_us': p['row']['total_latency'][2]['p99_us']}
                                 for p in summary['paths']])
            if not summary['complete']:
                raise RuntimeError('incomplete collector recording')
            if capacity:
                result['capacity'] = {'m': capacity[0], 'g': capacity[1]}
                result['bounded'] = (summary['health']['inflight'] <= capacity[0]
                                     and len(summary['paths']) <= capacity[1])
                result['retained_path_out_packets'] = sum(p['row']['total']['out_packets']
                                                         for p in summary['paths'])
                errors = summary['health']['errors']
                result['capacity_checks'] = {
                    'bounded': result['bounded'],
                    'association_error_reported': capacity[0] != 2 or errors['association_capacity'] > 0,
                    'path_error_reported': capacity[1] != 1 or errors['unrecorded_path_events'] > 0,
                    'global_success_retained': capacity[1] != 1 or
                        summary['health']['global']['out_packets'] > result['retained_path_out_packets'],
                    'existing_path_retained': bool(summary['paths']) and result['retained_path_out_packets'] > 0,
                    'independent_interval_capacity': errors['interval_capacity'] == 0,
                    'integrity': errors['integrity'] == 0,
                }
        return result
    finally:
        for process in reversed(processes):
            stop(process)
        for handle in handles:
            handle.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=HERE.parents[1] / 'bin/skbtop')
    parser.add_argument('--nslab', default='/home/captain/nslab/.venv/bin/nslab')
    parser.add_argument('--pairs', type=int, default=3)
    parser.add_argument('--seconds', type=int, default=8)
    arguments = parser.parse_args()
    if os.geteuid() != 0 or arguments.pairs < 1 or not 4 <= arguments.seconds <= 30:
        parser.error('requires root, positive pairs, and 4..30 seconds per bounded load')
    root = Path(tempfile.mkdtemp(prefix='skbtop-benchmark-'))
    root.chmod(0o755)
    binary = root / 'skbtop'
    shutil.copy2(arguments.binary, binary)
    (root / 'environment.json').write_text(json.dumps({
        'source': str(arguments.binary.resolve()), 'sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
        'version': run([str(binary), '-v']).strip(), 'kernel': run(['uname', '-a']).strip(),
        'iperf3': run(['iperf3', '--version']).splitlines()[0], 'cpu_count': os.cpu_count(),
        'seconds': arguments.seconds, 'pairs': arguments.pairs,
        'notes': ['Local built binary, shared WSL host; no production overhead claim.',
                  'RTT p99 is external ICMP RTT, distinct from collector stack latency.',
                  'Collector CPU excludes BPF hook execution charged to other contexts.',
                  'maps.json contains kernel map allocation reports, separate from RSS.'],
    }, indent=2) + '\n')
    lab = f'skbtop-bench-{uuid.uuid4().hex[:8]}'
    results = []
    print(f'Benchmark: {root}', flush=True)
    node_command = lambda target, *argv: [arguments.nslab, 'exec', '-n', lab, '-N', target, '--', *argv]
    node = lambda target, *argv: run(node_command(target, *argv))
    try:
        run([arguments.nslab, 'deploy', '-t', str(HERE / 'nslab-route.yaml'), '-n', lab])
        for target in ('h1', 'r1', 'h2'):
            node(target, 'sysctl', '-qw', 'net.ipv6.conf.all.disable_ipv6=1')
        node('h1', 'ping', '-4', '-c', '1', '-w', '5', '198.51.100.2')
        for source, device, target, peer_device, address in (
            ('h1', 'eth0', 'r1', 'eth0', '192.0.2.1'),
            ('r1', 'eth0', 'h1', 'eth0', '192.0.2.2'),
            ('r1', 'eth1', 'h2', 'eth0', '198.51.100.2'),
            ('h2', 'eth0', 'r1', 'eth1', '198.51.100.1')):
            mac = json.loads(node(target, 'ip', '-j', 'link', 'show', 'dev', peer_device))[0]['address']
            node(source, 'ip', 'neigh', 'replace', address, 'lladdr', mac, 'dev', device, 'nud', 'permanent')
        for rate in (10, 50):
            for pair in range(arguments.pairs):
                for observe in ((False, True) if pair % 2 == 0 else (True, False)):
                    name = f'{rate}mbps-pair{pair + 1}-{"collector" if observe else "baseline"}'
                    result = trial(node_command, binary, root / name, rate, arguments.seconds, observe)
                    results.append(result)
                    (root / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
                    print(json.dumps(result), flush=True)
        for name, capacity in (('path-capacity', (262144, 1)),
                               ('association-capacity', (2, 4096)), ('combined-capacity', (2, 1))):
            node('r1', 'tc', 'qdisc', 'replace', 'dev', 'eth1', 'root', 'netem', 'delay', '20ms')
            result = trial(node_command, binary, root / name, 10, arguments.seconds, True, capacity)
            results.append(result)
            (root / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
            print(json.dumps(result), flush=True)
            node('r1', 'tc', 'qdisc', 'del', 'dev', 'eth1', 'root')
        comparison = []
        for rate in (10, 50):
            row = {'offered_mbps': rate}
            for observe in (False, True):
                matches = [r for r in results if r['offered_mbps'] == rate
                           and r['observer'] == observe and 'capacity' not in r]
                row['collector' if observe else 'baseline'] = {
                    field: statistics.median(r[field] for r in matches)
                    for field in ('received_mbps', 'lost_percent', 'rtt_p99_ms', 'shared_host_busy_core_percent')}
            comparison.append(row)
        (root / 'comparison.json').write_text(json.dumps(comparison, indent=2) + '\n')
    finally:
        run([arguments.nslab, 'destroy', '-n', lab])
        (root / 'cleanup.txt').write_text(f'Destroyed {lab}\n')


if __name__ == '__main__':
    main()
