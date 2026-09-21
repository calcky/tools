# irqtop / irqstat

Two read-only Linux tools sharing a Rust binary, sampling every second.
irqstat defaults to hardware IRQs only and prints a compact timestamped table;
add `-s` to include softirqs. irqtop shows hardware IRQs and softirqs by default.
irqtop uses Ratatui and Crossterm to refresh a terminal with the busiest IRQs
first within each section. No Python is needed to run either tool.

The compiled executable is `irqtop`; `irqstat` is a relative symlink to it.
The invoked command name selects the display mode and defaults.

## Common commands

```sh
irqtop                         # All hardware IRQs + all softirqs (same as -a)
irqtop -n                      # Network hardware IRQs + NET_RX/NET_TX
irqtop -n -b                   # Also show host softnet statistics
irqtop -i nic0                  # nic0 hardware IRQs + host NET_RX/NET_TX
irqtop -i xnic0/vf0             # VF 0 passed through from PF xnic0
irqtop -n -m 500                # Only sources at or above 500/s
irqtop -n -z                   # Every non-zero network source
irqstat                        # All hardware IRQs only
irqstat -n                     # Network hardware IRQs only
irqstat -s                     # All hardware IRQs + all softirqs
irqstat -n -s                  # Network hardware IRQs + NET_RX/NET_TX
irqstat -n -b                  # Network hardware IRQs + host softnet
irqstat -n -s -b               # Hardware, software IRQs and softnet together
irqstat -i nic0,xnic0 -s        # Two interfaces + host NET_RX/NET_TX
irqstat -i xnic0,xnic1 1 5      # Five samples of two interfaces
irqstat -n -d 2 3              # Raw counts over each 2-second interval
irqstat -m 0 1 60 > irq.log     # Plain-text capture including idle sources
```

| Option | Meaning |
| --- | --- |
| `-a` | All hardware IRQs; all softirqs when enabled; default scope |
| `-n` | Network hardware IRQs; NET_RX/NET_TX when enabled |
| `-s` | Include softirqs in irqstat; already enabled in irqtop |
| `-b` | Add host-wide per-CPU softnet statistics |
| `-i NIC[,NIC]` | Exact interface or PF/vfN labels; implies `-n`, including when combined with `-a` |
| `-m RATE` | Minimum total rate per source; default `200/s` |
| `-z` | Show every non-zero source; `-m 0` also includes idle sources |
| `-d` | Raw interval counts instead of rates; `-m` still uses the rate per second |
| `-h` | Help |
| `-v` | Version |

`interval [count]` uses seconds and printed reports; decimals are supported.
The baseline is never printed or counted. Ctrl+C stops either command.
Only the short options above are supported. irqtop initially sorts by descending
rate within each section; irqstat sorts by IRQ. All CPUs are included.

## Reading the display

- irqstat uses `TIME IRQ/TYPE CPU NETDEV rate/s` columns. A source active on
  one CPU uses one row, with a label such as `CPU28`. Multiple active CPUs use
  `all` for the total, followed by compact CPU details; an idle source uses `-`.
  The scope and rate threshold print once, and the table header repeats roughly
  once per screen. A blank line separates samples. Empty samples have a timestamp
  and a short status message. Redirected irqtop uses the same text format.
- irqtop's header shows host local time, actual interval, matched/active sources
  and total rates. Its list has `HARD IRQ` and `SOFTIRQ` sections. Main columns are
  `IRQ / TYPE CPU NETDEV / SOURCE rate/s`; `CPU=all` is the row total.
- `NETDEV / SOURCE`: interface or PF/vfN label for hardware IRQs, `softirq`
  for softirqs, and `-` for unmapped hardware IRQs.
- In interactive mode, section headers and main rows are highlighted; hardware
  IRQs use cyan and softirqs use yellow. CPU details use compact labels such as
  `CPU30: 2442.92`, with muted labels and `|` separators between cells.
  Each IRQ's busiest CPU label and value are green and bold; exact ties are all
  highlighted. Other values use the normal terminal style and font size.
  Peaks use interval counts across all CPUs, including off-screen
  CPUs. Idle IRQs have no peak. CPU order stays numeric while values refresh.
- In irqtop the `rate/s` (or `count` with `-d`) column ends at the right edge
  inside the IRQ frame. irqstat and redirected irqtop use compact plain-text columns.
- Thin frames separate IRQ/softirq and optional SOFTNET, with their titles in
  the top borders. The selected scrolling area has a bright bold border;
  the other has a gray border. Tab moves the selection. Headers, per-IRQ totals,
  peak CPU values and anomaly colors retain their existing styles.
- In irqtop, hardware and softirq totals remain visible above the scrolling list and
  include matching rows below the display threshold. They are separate counts,
  not packet rates or a one-to-one hardware/softirq correspondence.
- `intr/s`: interrupts per second, using monotonic elapsed time.
- Following lines show non-zero per-CPU rates for that IRQ. The detail grid uses
  as many complete columns as fit the available width. For usual values irqtop
  fits four CPU columns at 80 characters and six at 120; larger values use fewer.
- The settings line reads `interval 1.007s | rate >= 200/s`.
  The default view hides sources below `200/s`; use `-z` for non-zero sources,
  or `-m 0` to include idle sources.

irqtop: **q** quit; **arrows/j/k** scroll; **PgUp/PgDn** page;
**a** show all hardware IRQs and all softirqs, clearing any interface selection;
**n** show network hardware IRQs and NET_RX/NET_TX;
**z** toggle between the default 200/s threshold and all non-zero sources;
**s** toggle sort; **b** show/hide softnet; **Tab** switch IRQ/softnet scrolling.
**Home/g** first page; **End/G** last page; mouse wheel scrolls.
Space and p also page down/up. Repeating a or n keeps the selected scope.
Headers and footer remain visible while the IRQ list scrolls. CPU values are
kept intact when the terminal resizes. The minimum size is 55 columns x 11 rows.
`NO_COLOR=1` keeps bold headers and peak CPUs with terminal-default colors. Redirected output
and `TERM=dumb` use plain text. Terminal settings/cursor/screen are restored
on q, Ctrl+C, SIGTERM, SIGHUP, errors and panic.

## Scope

irqstat reads softirq counters only with `-s`. irqtop samples hardware IRQs and
softirqs continuously, so changing scope keeps the counter baselines.
IRQ mapping uses sysfs device MSI/IRQ data, interface
names and virtio names.
PCI devices with network class 0x02 are included even without a host netdev,
including VFIO-bound SR-IOV VFs. PF virtfn links supply labels such as
xnic0/vf0; VFs with a host netdev keep that interface name. Other unbound
network PCI devices use their PCI address. Non-network VFIO devices are
excluded. Hardware rows only show IRQs present in /proc/interrupts;
allocated vectors without a registered host IRQ row are not fabricated.
VFIO figures are host-visible IRQ handler counts, not the guest's IRQ numbers,
guest CPU distribution or necessarily all hardware interrupt deliveries
(for example with posted interrupts). Use the tool inside the guest for
guest-side statistics. Selecting a PF with `-i` does not implicitly select VFs.
Mappings and resolved IRQ labels are cached. A hardware IRQ addition, removal,
or name change triggers a refresh on that sample; otherwise mappings refresh
on the first sample after five seconds. Device renames or driver changes that
leave the IRQ identities unchanged can take that long to appear. Counter reads
still happen at the requested interval. Exact -i filtering avoids nic0/xnic0 and VF name
collisions. Unknown interfaces fail clearly; virtual interfaces without
hardware IRQs have an empty hardware view; when softirqs are enabled, the host
network softirqs can still appear if they meet the threshold.

Shared IRQs and NIC administration vectors may include non-packet work.
USB NICs/shared hypervisor events may not map uniquely. Softirqs are per CPU,
not per interface: with `-i` and softirqs enabled, NET_RX/NET_TX still describe
the whole host.
IRQ/s is not PPS, CPU usage or handler
execution time. Add `-b` to inspect softnet counters for drops.

New/renamed IRQs, new CPUs and reset counters establish fresh baselines.
ERR/MIS summaries are excluded. Procfs snapshots are not atomic.

## Softnet

`-b` reads `/proc/net/softnet_stat` directly in the existing sampling loop.
It replaces the retired standalone `softnet.sh` script.
It adds an independent SOFTNET table below IRQs in irqtop and after each sample
in irqstat. No shell script or subprocess is used. Disabled softnet adds no
procfs reads. Pressing b establishes a fresh timed baseline; the panel can
briefly show sampling until the next report. Read/parse failures show an
unavailable status in this panel while IRQ sampling continues; recovery starts
with a fresh baseline.

| Column | Meaning |
| --- | --- |
| processed/s | Per-CPU receive processing count growth; not wire PPS |
| dropped/s | Packets dropped while enqueueing to receive backlog |
| squeeze/s | Receive processing exhausted its work/time budget; not a drop count |
| rps/s | RPS wakeup-related count growth, not packets |
| flow/s | RPS flow-limit drops, a subset of dropped; do not add them together |
| backlog | Current input + process queue length, not a rate or NIC ring depth |

With `-d`, the first five columns show interval counts and omit `/s`; backlog
always shows the current queue length. Each rate uses the monotonic time
between the corresponding softnet reads. The all row sums all sampled CPUs.
Idle CPUs are hidden, and the IRQ `-m`/`-z` filter does not apply to softnet.
CPUs with drops/flow-limit events appear first, then budget exhaustion, with
numeric CPU order within each group. Drops/flow are red, squeeze yellow, and
the peak processed CPU(s) green/bold; zeros are muted. Colors use raw nonzero
deltas, even if the displayed rate rounds to 0.00.

The lower frame keeps its column headers and all-CPU totals visible while
scrolling. Tab changes which panel arrows/j/k, paging and Home/End operate on.
Frames account for both border columns when wrapping data. Narrow windows
wrap the metric columns into multiple lines, repeating the CPU
label; no metric is omitted. Softnet needs more terminal rows than IRQ-only
mode; a small terminal shows the required dimensions. Plain output never uses
ANSI colors or box borders. With NO_COLOR, bold borders still identify the
selected area.

Softnet remains **host-wide** with `-i`: it cannot be attributed to a selected
NIC from this file. VF passthrough traffic handled inside guests need not
increase the host's softnet counters; inspect the guest for its receive work.
Hardware interrupts, NET_RX softirq invocations and processed counts measure
different work and need not match one-to-one.

Modern records supply real CPU IDs, including sparse online CPUs. Older
formats use the online CPU list and show `-` for unavailable backlog fields.
New CPUs establish a baseline. u32 decreases near the wrap boundary use
wrapping differences; other decreases reset the CPU baseline. Multiple wraps
between samples, or a reset near that boundary, cannot be distinguished from
these counters alone. The historical collision placeholder is omitted.

## Build and validation

The locked dependencies require Rust 1.88+; verified with Rust 1.96.
Ratatui 0.29 handles rendering, Crossterm 0.28 handles terminal/input, and
libc handles signals/local time. Once dependencies are cached, checks/builds
can run with --offline. Cargo.lock pins the tested dependencies.

From the tools repository root:

```sh
make                    # Build irqtop/target/release/irqtop and populate bin/
make check              # Formatting, unit tests and Clippy
./bin/irqtop -n
./bin/irqstat -n 1 5
sudo make install       # /usr/local/bin/irqtop and irqstat -> irqtop
```

Use `make install PREFIX="$HOME/.local"` for a per-user install. `DESTDIR` is
supported for staged packages. Build first, then install; installation does not
run Cargo. The build needs Cargo, GNU Make and standard Linux coreutils.

To build directly with Cargo:

```sh
cd irqtop
cargo build --release --locked
ln -sfn irqtop target/release/irqstat
./target/release/irqtop -n
./target/release/irqstat -n 1 5
```

Only one binary is compiled. When packaging a release, include the `irqtop`
executable and the `irqstat -> irqtop` link together in a tar archive so the
relative link is preserved.

## GitHub Actions builds

The `Build irqtop` workflow builds static Linux executables with musl, Rust
1.96.0 and cross 0.2.5. It runs on changes to `irqtop/` or the workflow, on
`irqtop-v*` tags, and manually from Actions > Build irqtop > Run workflow.

| Artifact architecture | Rust target |
| --- | --- |
| arm (32-bit ARMv7, hard-float) | `armv7-unknown-linux-musleabihf` |
| arm64 | `aarch64-unknown-linux-musl` |
| x86_64 | `x86_64-unknown-linux-musl` |

Each job runs unit tests (ARM targets use QEMU), checks that the executable has
no ELF interpreter or shared-library dependencies, and uploads a `.tar.gz`
with a matching `.sha256` file. Download them from the run's Artifacts section;
artifacts are kept for 30 days. A tag triggers builds, not a GitHub Release.

For example, the x86_64 package is `irqtop-v0.5.1-linux-x86_64-musl.tar.gz`:

```text
irqtop-v0.5.1-linux-x86_64-musl/
  irqtop
  irqstat -> irqtop
  README.md
```

After extracting the downloaded artifact ZIP:

```sh
sha256sum -c irqtop-v0.5.1-linux-x86_64-musl.tar.gz.sha256
tar -xzf irqtop-v0.5.1-linux-x86_64-musl.tar.gz
cd irqtop-v0.5.1-linux-x86_64-musl
./irqtop -n
./irqstat -n 1 5
```

Use the package for the target machine's architecture. ARM requires ARMv7
with hardware floating point; it does not target ARMv6 or soft-float systems.

## Validation

Validation includes procfs count bounds, PF/VF mappings, source selectors,
finite samples, Ratatui TestBackend cell contents/styles, 64-CPU paging,
window resizing, and terminal restoration. The read-only speed check uses
tests/verify-speed.py and tests/verify-pty.py; the latter needs Python with pyte 0.8.2
to reconstruct differential terminal updates. Use `--local` on other hosts
to skip the speed-specific nic0/xnic0/xnic1 mapping checks:

```sh
python3 tests/verify-speed.py /usr/local/bin
python3 tests/verify-speed.py ../bin --local
```

## CPU overhead

The sampling loop caches device mappings and IRQ labels, reuses the last report
when scrolling/resizing, and retains the previous snapshot without cloning the
current one. Idle terminal input waits for events instead of polling every 50 ms.
The wait is capped at 250 ms to keep signal handling responsive. Terminal size
uses ioctl directly, avoiding external tput commands when output is redirected.

Measure process CPU time in a 120x40 PTY with the standard-library-only benchmark:

```sh
python3 bench/benchmark.py ../bin --repeat 2
python3 bench/benchmark.py ../bin --compare-softnet
```

It runs irqstat -n and irqtop at 1-second and 0.1-second sample intervals,
one process at a time. CPU percentages are relative to one core and include
startup and mapping refreshes. Live IRQ activity and host load affect results.
