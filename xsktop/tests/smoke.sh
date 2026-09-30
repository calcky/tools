#!/usr/bin/env bash
set -euo pipefail

# Run as root with xdp-bench and xsktop paths; only isolated veth traffic is used.
XSKTOP=${1:?xsktop executable}
BENCH=${2:?xdp-bench executable}
MODE=${3:-skb}
OUTPUT=${4:-window}
PING_SIZE=${PING_SIZE:-56}
NS="xsktop-test-$$"
PEER="xskp$$"
LOG=$(mktemp -d /tmp/xsktop-test.XXXXXX)
BENCH_PID=
PING_PID=
cleanup() {
    [[ -z "$PING_PID" ]] || kill "$PING_PID" 2>/dev/null || true
    [[ -z "$BENCH_PID" ]] || kill -INT "$BENCH_PID" 2>/dev/null || true
    [[ -z "$BENCH_PID" ]] || wait "$BENCH_PID" 2>/dev/null || true
    ip link del "$PEER" 2>/dev/null || true
    ip netns del "$NS" 2>/dev/null || true
}
trap cleanup EXIT
ip netns add "$NS"
ip link add "$PEER" type veth peer name xsk0 netns "$NS"
ip link set "$PEER" address 02:00:00:00:01:01
ip -n "$NS" link set xsk0 address 02:00:00:00:01:02
ip addr add 192.0.2.1/30 dev "$PEER"
ip link set "$PEER" up
ip -n "$NS" link set lo up
ip -n "$NS" link set xsk0 up
ip neigh add 192.0.2.2 lladdr 02:00:00:00:01:02 dev "$PEER" nud permanent
ip netns exec "$NS" "$BENCH" xsk-tx -C copy -A "$MODE" -i 1 -d 10 xsk0 > "$LOG/bench.txt" 2>&1 &
BENCH_PID=$!
sleep 1
kill -0 "$BENCH_PID"
ping -n -i 0.02 -s "$PING_SIZE" -c 250 -W 1 192.0.2.2 > "$LOG/ping.txt" 2>&1 &
PING_PID=$!
if [[ "$OUTPUT" == text ]]; then
    ip netns exec "$NS" "$XSKTOP" -c 3 -d 1 -i xsk0 > "$LOG/terminal.txt"
    sed -n '1,18p' "$LOG/terminal.txt"
else
    (sleep 5; printf q) | script -q -e -c "stty rows 24 cols 120; TERM=xterm-256color ip netns exec '$NS' '$XSKTOP'" "$LOG/terminal.txt"
fi
tail -n 8 "$LOG/bench.txt"
printf '\nLogs: %s\n' "$LOG"
