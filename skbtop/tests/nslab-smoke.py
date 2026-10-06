#!/usr/bin/env python3
"""Record isolated route, NAT, bridge and egress-delay observations."""

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import uuid


HERE = Path(__file__).resolve().parent


def run(argv):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=25)
    if result.returncode:
        raise RuntimeError(f'{argv}: exit {result.returncode}\n{result.stdout}{result.stderr}')
    return result.stdout


def snapshots(directory):
    path = directory / 'snapshots.jsonl'
    if not path.exists():
        return []
    records = []
    for line in path.read_text().splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if record.get('type') == 'snapshot':
            records.append(record)
    return records


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def validate_summary(directory, pairs, local, classification):
    summary = json.loads((directory / 'summary.json').read_text())
    require(summary['complete'], f'incomplete recording: {summary.get("errors")}')
    require((directory / 'report.html').stat().st_size > 0, 'missing HTML report')
    require(bool(snapshots(directory)), 'no recorded snapshots')
    rows = [path['row'] for path in summary['paths']]
    final = snapshots(directory)[-1]['snapshot']
    require(not any(row['key']['kind'] == 'Forward' and
                    row['key']['ingress'] == row['key']['egress'] for row in rows),
            'unexpected same-interface FORWARD in non-hairpin fixture')
    require(not any(row['pending'] for row in final['rows']),
            'transmit associations remain pending after idle')
    if not local:
        require(not any(row['key']['kind'] == 'Input' for row in rows),
                'unexpected local INPUT on addressless bridge ports')
    measured = []
    for ingress, egress in pairs:
        matching = [row for row in rows if row['key']['kind'] == 'Forward'
                    and row['ingress_name'] == ingress and row['egress_name'] == egress]
        require(bool(matching), f'missing FORWARD {ingress} -> {egress}')
        row = matching[0]
        require(row['total']['out_packets'] > 0, f'no completed FORWARD {ingress} -> {egress}')
        require(row['total'][classification] > 0, f'missing {classification} classification')
        require(row['total'][classification] + row['total']['combo'] == row['total']['out_packets'],
                f'unclassified completions for {ingress} -> {egress}')
        require(row['total']['in_packets'] == row['total']['out_packets'],
                f'directional entry/completion mismatch for {ingress} -> {egress}')
        for latency in row['total_latency']:
            require(latency['samples'] > 0, f'missing complete latency for {ingress} -> {egress}')
            values = [latency[name] for name in ('min_us', 'avg_us', 'max_us')]
            require(all(value is not None and math.isfinite(value) and value >= 0 for value in values),
                    f'invalid latency for {ingress} -> {egress}')
            require(values[0] <= values[1] <= values[2], 'min/average/max are inconsistent')
        measured.append({'ingress': ingress, 'egress': egress, 'total': row['total'],
                         'queue_avg_us': row['total_latency'][1]['avg_us'],
                         'queue_p50_us': row['total_latency'][1]['p50_us']})
        if len(pairs) == 4 and classification == 'bridge':
            require(row['total']['out_packets'] == 3,
                    f'flood branch expected 3 completions for {ingress} -> {egress}')
    if local:
        for kind, field in (('Input', 'ingress_name'), ('Output', 'egress_name')):
            matching = [row for row in rows if row['key']['kind'] == kind and row[field] == 'eth0']
            require(bool(matching), f'missing local {kind} eth0')
            stages = matching[0]['total_latency']
            require(stages[0 if kind == 'Input' else 2]['samples'] > 0, f'no local {kind} latency')
            if kind == 'Input':
                require(all(stage['samples'] == 0 and stage['sum_ns'] == 0
                            and not any(stage['histogram']) for stage in stages[1:]),
                        'INPUT must not record Queue or Total')
    require(summary['reconciliation']['counters_match'], 'interval/cumulative counters differ')
    require(summary['reconciliation']['latency_matches'], 'interval/cumulative latency differs')
    return {'paths': measured, 'health': summary['health'],
            'reconciliation': summary['reconciliation'], 'snapshot_count': summary['snapshot_count']}


def traffic(node, source, destination, family):
    return node(source, 'ping', f'-{family}', '-c', '3', '-i', '0.2', '-w', '5', destination)


def scenario(name, nslab, binary, root, bridge_probe=None, bridge_nf=None):
    routed = name in ('route', 'nat', 'netem')
    fixture = 'nslab-route.yaml' if routed else ('nslab-bridge-flood.yaml' if name == 'flood' else 'nslab-bridge.yaml')
    observer = 'r1' if routed else 'sw1'
    interfaces = 'eth0,eth1' if routed else ('swp1,swp2,swp3' if name == 'flood' else 'swp1,swp2')
    lab = f'skbtop-{name}-{uuid.uuid4().hex[:8]}'
    directory = root / name
    directory.mkdir()
    node = lambda target, *argv: run([nslab, 'exec', '-n', lab, '-N', target, '--', *argv])
    process = None
    probe = None
    probe_log = None
    outcome = {'case': name, 'lab': lab, 'recording': str(directory), 'ok': False}
    try:
        run([nslab, 'deploy', '-t', str(HERE / fixture), '-n', lab])
        for target in ('h1', 'h2', observer) + (('h3',) if name == 'flood' else ()):
            node(target, 'sysctl', '-qw', 'net.ipv6.conf.all.accept_ra=0')
            if name == 'flood' or target == 'sw1':
                node(target, 'sysctl', '-qw', 'net.ipv6.conf.all.disable_ipv6=1')
        if not routed and bridge_nf is not None:
            node(observer, 'sysctl', '-qw',
                 f'net.bridge.bridge-nf-call-iptables={bridge_nf}',
                 f'net.bridge.bridge-nf-call-ip6tables={bridge_nf}',
                 f'net.bridge.bridge-nf-call-arptables={bridge_nf}')
        (root / f'{name}.interfaces.json').write_text(json.dumps({
            'links': json.loads(node(observer, 'ip', '-j', '-d', 'link', 'show')),
            'netns': node(observer, 'readlink', '/proc/self/ns/net').strip(),
            'selected': interfaces.split(','),
            'bridge_nf': json.loads(node(observer, 'python3', '-c',
                'import json; from pathlib import Path; '
                'print(json.dumps({p.name:p.read_text().strip() '
                'for p in Path("/proc/sys/net/bridge").glob("bridge-nf-*")}))')),
            'modules': Path('/proc/modules').read_text().splitlines(),
        }, indent=2) + '\n')
        destination4 = '198.51.100.2' if routed else '192.0.2.3'
        destination6 = '2001:db8:2::2' if routed else '2001:db8:3::3'
        node('h1', 'ping', '-4', '-c', '1', '-w', '5', destination4)
        if name != 'flood':
            node('h1', 'ping', '-6', '-c', '1', '-w', '5', destination6)
        neighbors = (
            [('h1', 'eth0', 'r1', 'eth0', ['192.0.2.1', '2001:db8:1::1']),
             ('r1', 'eth0', 'h1', 'eth0', ['192.0.2.2', '2001:db8:1::2']),
             ('r1', 'eth1', 'h2', 'eth0', ['198.51.100.2', '2001:db8:2::2']),
             ('h2', 'eth0', 'r1', 'eth1', ['198.51.100.1', '2001:db8:2::1'])]
            if routed else
            [('h1', 'eth0', 'h2', 'eth0', ['192.0.2.3', '2001:db8:3::3']),
             ('h2', 'eth0', 'h1', 'eth0', ['192.0.2.2', '2001:db8:3::2'])])
        for source, device, target, peer_device, addresses in neighbors:
            mac = json.loads(node(target, 'ip', '-j', 'link', 'show', 'dev', peer_device))[0]['address']
            for address in addresses[:1] if name == 'flood' else addresses:
                node(source, 'ip', 'neigh', 'replace', address, 'lladdr', mac,
                     'dev', device, 'nud', 'permanent')
        if name == 'nat':
            node('r1', 'nft', 'add', 'table', 'inet', 'skbtop_test')
            node('r1', 'nft', 'add', 'chain', 'inet', 'skbtop_test', 'postrouting',
                 '{ type nat hook postrouting priority srcnat; policy accept; }')
            for family, subnet in (('ip', '192.0.2.0/24'), ('ip6', '2001:db8:1::/64')):
                node('r1', 'nft', 'add', 'rule', 'inet', 'skbtop_test', 'postrouting',
                     'oifname', 'eth1', family, 'saddr', subnet, 'counter', 'masquerade')
        if name == 'netem':
            node('r1', 'tc', 'qdisc', 'replace', 'dev', 'eth1', 'root', 'netem', 'delay', '20ms')
        log = root / f'{name}.collector.log'
        with log.open('w') as output:
            process = subprocess.Popen([nslab, 'exec', '-n', lab, '-N', observer, '--', str(binary),
                                        '-i', interfaces, '-d', '0.25', '-c', '160', '-T', '40',
                                        '-o', str(directory)], stdout=output, stderr=subprocess.STDOUT)
            deadline = time.monotonic() + 30
            while not snapshots(directory):
                require(process.poll() is None, f'collector startup failed; see {log}')
                require(time.monotonic() < deadline, f'collector startup timed out; see {log}')
                time.sleep(0.1)
            if bridge_probe and not routed:
                pids = [p.parent.name for p in Path('/proc').glob('[0-9]*/exe')
                        if p.resolve() == binary]
                require(len(pids) == 1, 'cannot identify collector for bridge diagnostic')
                ids = set()
                for path in (Path('/proc') / pids[0] / 'fdinfo').iterdir():
                    for line in path.read_text().splitlines():
                        if line.startswith('map_id:'):
                            ids.add(int(line.split()[1]))
                maps = json.loads(run(['bpftool', '-j', 'map', 'show']))
                origin = [m for m in maps if m['id'] in ids and m['name'] == 'origins']
                require(len(origin) == 1, 'cannot identify collector origins map')
                probe_path = root / f'{name}.bridge-probe.log'
                probe_log = probe_path.open('w')
                probe = subprocess.Popen([str(bridge_probe), str(origin[0]['id'])],
                                         stdout=probe_log, stderr=subprocess.STDOUT)
                deadline = time.monotonic() + 5
                while 'Attached' not in probe_path.read_text():
                    require(probe.poll() is None and time.monotonic() < deadline,
                            f'bridge diagnostic startup failed; see {probe_path}')
                    time.sleep(0.1)
            traffic_log = [traffic(node, 'h1', destination4, 4)]
            if name != 'flood':
                traffic_log.append(traffic(node, 'h1', destination6, 6))
                traffic_log.append(traffic(node, 'h2', '192.0.2.2', 4))
                traffic_log.append(traffic(node, 'h2', '2001:db8:1::2' if routed else '2001:db8:3::2', 6))
            if routed:
                traffic_log.append(traffic(node, 'r1', '192.0.2.2', 4))
                traffic_log.append(traffic(node, 'r1', '2001:db8:1::2', 6))
            (root / f'{name}.ping.log').write_text('\n'.join(traffic_log))
            require(process.wait(timeout=50) == 0, f'collector failed; see {log}')
        pairs = [('eth0', 'eth1'), ('eth1', 'eth0')] if routed else [('swp1', 'swp2'), ('swp2', 'swp1')]
        if name == 'flood':
            pairs += [('swp1', 'swp3'), ('swp2', 'swp3')]
            (root / 'flood.fdb.json').write_text(node('sw1', 'bridge', '-j', 'fdb', 'show', 'br', 'br0'))
        outcome.update(validate_summary(directory, pairs, routed, 'route' if routed else 'bridge'))
        if name == 'nat':
            rules = node('r1', 'nft', '-j', 'list', 'table', 'inet', 'skbtop_test')
            (root / 'nat.rules.json').write_text(rules)
            matches = []
            for entry in json.loads(rules)['nftables']:
                for expression in entry.get('rule', {}).get('expr', []):
                    if 'counter' in expression:
                        matches.append(expression['counter']['packets'])
            require(len(matches) == 2 and all(count > 0 for count in matches), 'NAT rules did not match both families')
            outcome['nat_rule_packets'] = matches
        if name == 'netem':
            (root / 'netem.qdisc.json').write_text(node('r1', 'tc', '-j', '-s', 'qdisc', 'show', 'dev', 'eth1'))
            require(outcome['paths'][0]['queue_avg_us'] >= 15000, '20ms netem absent from forward queue latency')
        outcome['ok'] = True
    except Exception as error:
        outcome['error'] = str(error)
    finally:
        if probe is not None:
            try:
                probe.wait(timeout=12)
            except subprocess.TimeoutExpired:
                probe.terminate()
                probe.wait(timeout=5)
        if probe_log is not None:
            probe_log.close()
        if process is not None and process.poll() is None:
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.terminate()
                process.wait(timeout=5)
        try:
            run([nslab, 'destroy', '-n', lab])
            outcome['cleanup'] = 'destroyed'
        except Exception as error:
            outcome['cleanup_error'] = str(error)
            outcome['ok'] = False
    return outcome


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=HERE.parent.parent / 'bin/skbtop')
    parser.add_argument('--nslab', default=shutil.which('nslab'))
    parser.add_argument('--case', action='append', choices=('route', 'nat', 'netem', 'bridge', 'flood'))
    parser.add_argument('--bridge-probe', type=Path, help='optional compiled libbpf hook diagnostic')
    parser.add_argument('--bridge-nf', type=int, choices=(0, 1), help='bridge netfilter setting in the owned lab')
    arguments = parser.parse_args()
    require(os.geteuid() == 0, 'run from a root shell')
    require(arguments.nslab is not None, 'nslab is required on PATH')
    require(arguments.binary.is_file(), 'build skbtop before running the fixture')
    root = Path(tempfile.mkdtemp(prefix='skbtop-validation-'))
    root.chmod(0o755)
    binary = root / 'skbtop'
    shutil.copy2(arguments.binary, binary)
    (root / 'binary.json').write_text(json.dumps({
        'source': str(arguments.binary.resolve()),
        'version': run([str(binary), '-v']).strip(),
        'sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
    }, indent=2) + '\n')
    print(f'Recordings: {root}', flush=True)
    outcomes = []
    for name in arguments.case or ('route', 'nat', 'netem', 'bridge', 'flood'):
        outcome = scenario(name, arguments.nslab, binary, root, arguments.bridge_probe, arguments.bridge_nf)
        outcomes.append(outcome)
        (root / 'validation.json').write_text(json.dumps(outcomes, indent=2) + '\n')
        print(json.dumps(outcome), flush=True)
    raise SystemExit(0 if all(outcome['ok'] for outcome in outcomes) else 1)


if __name__ == '__main__':
    main()
