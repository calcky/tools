#!/usr/bin/env python3
"""Validate live identities, forwarding branches and software segmentation."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time
import uuid


HERE = Path(__file__).resolve().parent


def run(argv):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError(f'{argv}: {result.stdout}{result.stderr}')
    return result.stdout


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def snapshots(directory):
    path = directory / 'snapshots.jsonl'
    records = []
    if path.exists():
        for line in path.read_text().splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if item.get('type') == 'snapshot':
                records.append(item['snapshot'])
    return records


def wait_for(process, directory, predicate):
    deadline = time.monotonic() + 30
    while True:
        values = snapshots(directory)
        if values and predicate(values[-1]):
            return values[-1]
        require(process.poll() is None, f'collector exited before condition: {directory}')
        require(time.monotonic() < deadline, f'condition timed out: {directory}')
        time.sleep(0.05)


def stop(process, binary):
    if process.poll() is None:
        targets = []
        for path in Path('/proc').glob('[0-9]*/exe'):
            try:
                if path.resolve() == binary:
                    targets.append(int(path.parent.name))
            except OSError:
                pass
        require(len(targets) == 1, 'cannot identify the isolated collector')
        # Signal the collector directly; interrupting nslab also cancels its
        # wrapper and may terminate the child before recording finalization.
        os.kill(targets[0], signal.SIGINT)
    try:
        require(process.wait(timeout=10) == 0, 'collector exit failed')
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)
        raise


def scenario(name, nslab, binary, root):
    bridge = name in ('hairpin', 'bridge-netfilter')
    fixture = 'nslab-bridge-flood.yaml' if name == 'hairpin' else (
        'nslab-bridge.yaml' if bridge else 'nslab-route.yaml')
    observer = 'sw1' if bridge else 'r1'
    lab = f'skbtop-lifecycle-{uuid.uuid4().hex[:8]}'
    directory = root / name
    directory.mkdir()
    node = lambda target, *argv: run([nslab, 'exec', '-n', lab, '-N', target, '--', *argv])
    process = None
    server = None
    deployed = False
    outcome = {'case': name, 'ok': False, 'recording': str(directory)}
    try:
        run([nslab, 'deploy', '-t', str(HERE / fixture), '-n', lab])
        deployed = True
        targets = ('h1', 'h2', observer) + (('h3',) if name == 'hairpin' else ())
        for target in targets:
            node(target, 'sysctl', '-qw', 'net.ipv6.conf.all.accept_ra=0')
            if name != 'bridge-netfilter':
                node(target, 'sysctl', '-qw', 'net.ipv6.conf.all.disable_ipv6=1')
        if name == 'hairpin':
            node(observer, 'bridge', 'link', 'set', 'dev', 'swp1', 'hairpin', 'on')
        if name == 'bridge-netfilter':
            for parameter in ('bridge-nf-call-iptables', 'bridge-nf-call-ip6tables'):
                node(observer, 'sysctl', '-qw', f'net.bridge.{parameter}=1')
            node(observer, 'nft', 'add', 'table', 'inet', 'skbtop_test')
            node(observer, 'nft', 'add', 'chain', 'inet', 'skbtop_test', 'forward',
                 '{ type filter hook forward priority filter; policy accept; }')
            node(observer, 'nft', 'add', 'rule', 'inet', 'skbtop_test', 'forward',
                 'meta', 'nfproto', 'ipv4', 'counter')
            node(observer, 'nft', 'add', 'rule', 'inet', 'skbtop_test', 'forward',
                 'meta', 'nfproto', 'ipv6', 'counter')
        if name in ('selection', 'bridge-netfilter'):
            destination = '192.0.2.3' if bridge else '198.51.100.2'
            node('h1', 'ping', '-4', '-c', '1', '-w', '5', destination)
            if bridge:
                node('h1', 'ping', '-6', '-c', '1', '-w', '5', '2001:db8:3::3')
        options = ['-i', 'eth0,eth1'] if name == 'selection' else []
        with (root / f'{name}.collector.log').open('w') as log:
            process = subprocess.Popen([nslab, 'exec', '-n', lab, '-N', observer, '--',
                                        str(binary), '-d', '0.2', '-c', '400', '-T', '80',
                                        '-o', str(directory), *options], stdout=log,
                                       stderr=subprocess.STDOUT, start_new_session=True)
            wait_for(process, directory, lambda _: True)
            if name == 'dynamic':
                def add_device(index=None):
                    arguments = ['ip', 'link', 'add', 'name', 'dyn0']
                    if index is not None:
                        arguments += ['index', str(index)]
                    node(observer, *arguments, 'type', 'dummy')
                    node(observer, 'ip', 'addr', 'add', '10.44.0.1/24', 'dev', 'dyn0')
                    node(observer, 'ip', 'link', 'set', 'dyn0', 'up')
                    node(observer, 'ip', 'neigh', 'replace', '10.44.0.2', 'lladdr',
                         '02:00:00:00:44:02', 'dev', 'dyn0', 'nud', 'permanent')
                    return json.loads(node(observer, 'ip', '-j', 'link', 'show', 'dyn0'))[0]['ifindex']

                def send():
                    node(observer, 'python3', '-c',
                         'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); '
                         '[s.sendto(b"x"*96,("10.44.0.2",11111)) for _ in range(3)]')

                index = add_device()
                current = wait_for(process, directory,
                                   lambda s: any(i['name'] == 'dyn0' for i in s['interfaces']))
                generation = next(i['generation'] for i in current['interfaces'] if i['name'] == 'dyn0')
                send()
                wait_for(process, directory, lambda s: any(
                    r['key']['egress'] == index and r['total']['out_packets'] >= 3 for r in s['rows']))
                node(observer, 'ip', 'link', 'set', 'dyn0', 'name', 'renamed0')
                wait_for(process, directory,
                         lambda s: any(i['name'] == 'renamed0' for i in s['interfaces']))
                send()
                wait_for(process, directory, lambda s: any(
                    r['egress_name'] == 'renamed0' and r['total']['out_packets'] >= 6 for r in s['rows']))
                node(observer, 'ip', 'link', 'del', 'renamed0')
                require(add_device(index) == index, 'ifindex reuse was not exercised')
                wait_for(process, directory, lambda s: any(
                    i['ifindex'] == index and i['alive'] and i['generation'] != generation
                    for i in s['interfaces']))
                send()
                wait_for(process, directory, lambda s: any(
                    r['key']['egress'] == index and r['key']['egress_generation'] != generation
                    and r['total']['out_packets'] >= 3 for r in s['rows']))
                outcome.update(ifindex=index, first_generation=generation)
            elif name == 'selection':
                node('h1', 'ping', '-4', '-c', '3', '-i', '.1', '-w', '5', '198.51.100.2')
                before = wait_for(process, directory, lambda s: any(
                    r['key']['kind'] == 'Forward' and r['ingress_name'] == 'eth0'
                    and r['total']['out_packets'] >= 3 for r in s['rows']))
                key = next(r['key'] for r in before['rows'] if
                           r['key']['kind'] == 'Forward' and r['ingress_name'] == 'eth0')
                node(observer, 'ip', 'link', 'set', 'eth0', 'name', 'uplink0')
                wait_for(process, directory,
                         lambda s: any(i['name'] == 'uplink0' for i in s['interfaces']))
                node('h1', 'ping', '-4', '-c', '3', '-i', '.1', '-w', '5', '198.51.100.2')
                wait_for(process, directory, lambda s: any(
                    r['key'] == key and r['ingress_name'] == 'uplink0'
                    and r['total']['out_packets'] >= 6 for r in s['rows']))
                outcome['renamed_path_key'] = key
            elif name == 'hairpin':
                node('h1', 'python3', '-c',
                     'import socket; from pathlib import Path; '
                     's=socket.socket(socket.AF_PACKET,socket.SOCK_RAW); s.bind(("eth0",0)); '
                     'mac=bytes.fromhex(Path("/sys/class/net/eth0/address").read_text().strip().replace(":","")); '
                     '[s.send(b"\\xff"*6+mac+b"\\x88\\xb5"+b"x"*64) for _ in range(3)]')
                wait_for(process, directory, lambda s: any(
                    r['key']['kind'] == 'Forward' and r['ingress_name'] == 'swp1'
                    and r['egress_name'] == 'swp1' and r['total']['out_packets'] == 3 for r in s['rows']))
            elif name == 'gso':
                node(observer, 'ethtool', '-K', 'eth1', 'tso', 'off', 'gso', 'off')
                (root / 'gso.features.txt').write_text(node(observer, 'ethtool', '-k', 'eth1'))
                with (root / 'gso.server.json').open('w') as output:
                    server = subprocess.Popen([nslab, 'exec', '-n', lab, '-N', 'h2', '--',
                                               'iperf3', '-s', '-1', '-J'], stdout=output,
                                              stderr=subprocess.STDOUT, start_new_session=True)
                    # nslab starts the namespace command asynchronously; give
                    # iperf3 time to bind before the client connects.
                    time.sleep(0.5)
                    result = node('h1', 'iperf3', '-c', '198.51.100.2', '-t', '3', '-J')
                    (root / 'gso.client.json').write_text(result)
                    require('error' not in json.loads(result), 'TCP segmentation load failed')
                    require(server.wait(timeout=10) == 0, 'TCP load server failed')
                completed = wait_for(process, directory, lambda s: any(
                    r['key']['kind'] == 'Forward' and r['ingress_name'] == 'eth0'
                    and r['total']['out_packets'] > r['total']['in_packets'] for r in s['rows']))
                outcome['segmented_path'] = next(r['total'] for r in completed['rows']
                                                if r['key']['kind'] == 'Forward'
                                                and r['ingress_name'] == 'eth0')
            else:
                for family, address in ((4, '192.0.2.3'), (6, '2001:db8:3::3')):
                    node('h1', 'ping', f'-{family}', '-c', '3', '-i', '.1', '-w', '5', address)
                wait_for(process, directory, lambda s: sum(
                    r['total']['out_packets'] for r in s['rows'] if r['key']['kind'] == 'Forward') >= 12)
                rules = json.loads(node(observer, 'nft', '-j', 'list', 'table', 'inet', 'skbtop_test'))
                counts = [expression['counter']['packets'] for entry in rules['nftables']
                          for expression in entry.get('rule', {}).get('expr', []) if 'counter' in expression]
                require(len(counts) == 2 and all(n >= 6 for n in counts), 'dual-stack bridge netfilter not exercised')
                (root / 'bridge-netfilter.rules.json').write_text(json.dumps(rules, indent=2) + '\n')
                outcome['netfilter_packets'] = counts
            time.sleep(0.4)
            stop(process, binary)
        summary = json.loads((directory / 'summary.json').read_text())
        require(summary['complete'], 'incomplete recording')
        require(summary['reconciliation']['counters_match'] and summary['reconciliation']['latency_matches'],
                'interval/cumulative reconciliation failed')
        rows = [item['row'] for item in summary['paths']]
        require(not any(r['pending'] for r in rows), 'transmit pending remains after idle')
        require(summary['health']['errors']['integrity'] == 0, 'accounting integrity error')
        if name == 'dynamic':
            versions = [r for r in rows if r['key']['kind'] == 'Output' and r['key']['egress'] == index]
            require(len(versions) == 2, 'recreated device did not retain separate path identities')
            require(sorted(r['total']['out_packets'] for r in versions) == [3, 6], 'device lifetimes mixed counts')
            require(any(r['egress_name'] == 'renamed0 [gone]' for r in versions), 'deleted label not retained')
        if bridge:
            forwarded = [r for r in rows if r['key']['kind'] == 'Forward']
            require(all(r['total']['bridge'] == r['total']['out_packets'] for r in forwarded),
                    'missing or duplicate bridge classification')
            require(all(r['total']['in_packets'] == r['total']['out_packets'] for r in forwarded),
                    'bridge directional branch counts differ')
            if name == 'hairpin':
                require(len(forwarded) == 3 and all(r['total']['out_packets'] == 3 for r in forwarded),
                        'hairpin broadcast branches were duplicated or omitted')
        outcome.update(ok=True, health=summary['health'], paths=[
            {'key': r['key'], 'ingress': r['ingress_name'], 'egress': r['egress_name'], 'total': r['total']}
            for r in rows])
    except Exception as error:
        outcome['error'] = str(error)
    finally:
        if server and server.poll() is None:
            os.killpg(server.pid, signal.SIGTERM)
            server.wait(timeout=5)
        if process and process.poll() is None:
            stop(process, binary)
        if deployed:
            run([nslab, 'destroy', '-n', lab])
        outcome['cleanup'] = 'destroyed' if deployed else 'not deployed'
    return outcome


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--nslab', default=shutil.which('nslab') or '/home/captain/nslab/.venv/bin/nslab')
    parser.add_argument('--binary', type=Path, default=HERE.parent.parent / 'bin/skbtop')
    parser.add_argument('--case', action='append', choices=['dynamic', 'selection', 'hairpin', 'bridge-netfilter', 'gso'])
    options = parser.parse_args()
    require(os.geteuid() == 0, 'run from a root shell')
    root = Path(tempfile.mkdtemp(prefix='skbtop-lifecycle-'))
    root.chmod(0o755)
    binary = root / 'skbtop'
    shutil.copy2(options.binary, binary)
    (root / 'binary.json').write_text(json.dumps({
        'source': str(options.binary.resolve()), 'sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
        'version': run([str(binary), '-v']).strip()}, indent=2) + '\n')
    print(f'Validation: {root}', flush=True)
    outcomes = []
    for case in options.case or ['dynamic', 'selection', 'hairpin', 'bridge-netfilter', 'gso']:
        outcome = scenario(case, options.nslab, binary, root)
        outcomes.append(outcome)
        (root / 'validation.json').write_text(json.dumps(outcomes, indent=2) + '\n')
        print(json.dumps(outcome), flush=True)
    raise SystemExit(0 if all(result['ok'] for result in outcomes) else 1)


if __name__ == '__main__':
    main()
