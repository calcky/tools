"""Read-only counter/CLI checks plus a real terminal test; no traffic changes."""
import argparse
from collections import Counter
from pathlib import Path
import re
import subprocess
import sys

parser = argparse.ArgumentParser()
parser.add_argument('root', type=Path)
parser.add_argument('--local', action='store_true', help='Skip speed-specific PCI mappings')
args = parser.parse_args()
exe = str(args.root / 'irqstat')


def run(*options):
    return subprocess.check_output([exe, *options], text=True, timeout=8)


def rows(output):
    return [line.split()[1:] for line in output.splitlines()
            if re.match(r'^\d{2}:\d{2}:\d{2}\s+\S+\s+(?:CPU\d+|all|-)\s+\S+\s+\d+(?:\.\d+)?\s*$', line)]


def counts(path):
    lines = Path(path).read_text().splitlines()
    n = len(lines[0].split())
    result = {}
    for line in lines[1:]:
        key, _, rest = line.partition(':')
        fields = rest.split()
        if len(fields) >= n and all(x.isdigit() for x in fields[:n]):
            result[key.strip()] = sum(map(int, fields[:n]))
    return result


before = counts('/proc/interrupts')
soft_before = counts('/proc/softirqs')
output = run('-n', '-s', '-m', '0', '-d', '0.3', '1')
after = counts('/proc/interrupts')
soft_after = counts('/proc/softirqs')
network_rows = [r for r in rows(output) if r[2] != 'softirq']
soft_rows = [r for r in rows(output) if r[2] == 'softirq']
assert {r[0] for r in soft_rows} == {'NET_RX', 'NET_TX'}
if not args.local:
    expected = set()
    for device in Path('/sys/bus/pci/devices').iterdir():
        if int((device / 'class').read_text().strip(), 16) >> 16 == 2:
            expected.update(p.name for p in (device / 'msi_irqs').glob('*'))
    assert {r[0] for r in network_rows} == expected.intersection(before), output
    assert {'nic0', 'xnic0', 'xnic1', 'xnic0/vf0', 'xnic1/vf0'} <= {r[2] for r in network_rows}
    vf = [r for r in rows(run('-i', 'xnic0/vf0', '-m', '0', '0.1', '1')) if r[2] != 'softirq']
    assert vf and {r[2] for r in vf} == {'xnic0/vf0'}
    filtered = run('-i', 'nic0', '-m', '0', '0.1', '2')
    assert filtered.count('irqstat |') == 1 and 'xnic' not in filtered
    assert set(Counter(row[0] for row in rows(filtered)).values()) == {2}
    assert not any(r[2] == 'softirq' for r in rows(filtered))
    filtered_soft = run('-i', 'nic0', '-s', '-m', '0', '0.1', '1')
    assert {r[0] for r in rows(filtered_soft) if r[2] == 'softirq'} == {'NET_RX', 'NET_TX'}
    multi = rows(run('-i', 'nic0,xnic0/vf0', '-m', '0', '0.1', '1'))
    assert {r[2] for r in multi if r[2] != 'softirq'} == {'nic0', 'xnic0/vf0'}
for row in network_rows:
    assert 0 <= int(row[3]) <= after[row[0]] - before[row[0]], row
assert '\x1b' not in output
for row in soft_rows:
    assert 0 <= int(row[3]) <= soft_after[row[0]] - soft_before[row[0]], row
for selectors in [[], ['-a'], ['-n']]:
    hard_only = run(*selectors, '-m', '0', '0.1', '1')
    assert not any(row[2] == 'softirq' for row in rows(hard_only))
    assert '+' not in hard_only.splitlines()[0]
    mixed = run(*selectors, '-s', '-m', '0', '0.1', '1')
    assert any(row[2] == 'softirq' for row in rows(mixed))
    if selectors != ['-n'] or not args.local:
        assert any(row[2] != 'softirq' for row in rows(mixed))
    soft_ids = {r[0] for r in rows(mixed) if r[2] == 'softirq'}
    if selectors == ['-n']:
        assert soft_ids == {'NET_RX', 'NET_TX'}
    else:
        assert soft_ids == set(soft_before)
        assert {r[0] for r in rows(mixed) if r[2] != 'softirq'} == set(before)
    assert {r[0] for r in rows(hard_only)} == {r[0] for r in rows(mixed) if r[2] != 'softirq'}
    assert '\x1b' not in mixed
    assert 'CPU columns' not in mixed and 'Filter' not in mixed
default = run('0.1', '1')
assert 'rate >= 200/s' in default
assert all(float(row[3]) >= 200 for row in rows(default))
help_text = run('-h')
assert '--' not in help_text
for option in ['-a', '-n', '-s', '-b', '-i', '-m', '-z', '-d', '-h', '-v']:
    assert option in help_text
for name in ['irqtop', 'irqstat']:
    binary = str(args.root / name)
    assert subprocess.check_output([binary, '-v'], text=True).strip() == f'{name} 0.5.1'
    invalid = subprocess.run([binary, '--invalid'], capture_output=True, text=True, timeout=3)
    assert invalid.returncode != 0 and invalid.stderr.startswith(f'{name}: '), invalid
for removed in ['-A', '-N', '-P', '-I', '-t', '-V', '-S', '--all-hard', '--net-hard',
                '--all-soft', '--net-soft', '--device', '--numa', '--min-rate',
                '--sort', '--delta', '--since-boot', '--help', '--version']:
    bad = subprocess.run([exe, removed], capture_output=True, text=True, timeout=3)
    assert bad.returncode != 0 and 'unknown option' in bad.stderr, (removed, bad)
bad = subprocess.run([exe, '-i', 'nonexistent'], capture_output=True, text=True)
assert bad.returncode != 0 and 'does not exist' in bad.stderr


def softnet_counts():
    return {int(fields[12], 16): [int(fields[i], 16) for i in [0, 1, 2, 9, 10, 11]]
            for line in Path('/proc/net/softnet_stat').read_text().splitlines()
            if len(fields := line.split()) >= 13}


def softnet_rows(output):
    result = {}
    section = output.split('SOFTNET | host |')[1]
    for line in section.splitlines():
        fields = line.split()
        if fields and (fields[0] == 'all' or re.fullmatch(r'CPU\d+', fields[0])):
            result.setdefault(fields[0], []).extend(fields[1:])
    assert all(len(values) == 6 for values in result.values()), result
    return result


net_before = softnet_counts()
net_output = run('-n', '-b', '-d', '-m', '999999999', '0.3', '1')
net_after = softnet_counts()
assert not any(row[2] == 'softirq' for row in rows(net_output))
net_rows = softnet_rows(net_output)
assert 'all' in net_rows and 'processed/s' not in net_output
for cpu, values in net_rows.items():
    if cpu == 'all':
        continue
    cpu_id = int(cpu[3:])
    assert cpu_id in net_before and cpu_id in net_after
    for i, value in enumerate(values[:5]):
        assert 0 <= int(value) <= (net_after[cpu_id][i] - net_before[cpu_id][i]) % (2**32), (cpu, i, value)
for i in range(6):
    assert int(net_rows['all'][i]) == sum(int(v[i]) for cpu, v in net_rows.items() if cpu != 'all')
assert '\x1b' not in net_output
assert 'SOFTNET' not in default
net_rate = run('-n', '-s', '-b', '-m', '0', '0.2', '1')
assert 'processed/s' in net_rate and 'backlog' in net_rate
assert {r[0] for r in rows(net_rate) if r[2] == 'softirq'} == {'NET_RX', 'NET_TX'}
assert all(float(v) >= 0 for values in softnet_rows(net_rate).values() for v in values)
net_interface = next(path.name for path in Path('/sys/class/net').iterdir() if path.name != 'lo')
net_selected = run('-i', net_interface, '-b', '0.1', '1')
assert 'SOFTNET | host' in net_selected and 'all' in softnet_rows(net_selected)
print('PASS: softnet host scope, -b/-s independence, deltas within procfs bounds, gauges, totals and rates', flush=True)
print(f'PASS: {len(network_rows)} network IRQs, stat hard-only default / -s opt-in, hard/soft counter bounds, CLI, 200/s default, compact output' + ('' if args.local else ', speed PF/VF mapping'), flush=True)
subprocess.run([sys.executable, str(Path(__file__).with_name('verify-pty.py')), str(args.root)], check=True)
