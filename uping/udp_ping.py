#!/usr/bin/env python3
"""Small UDP request/response ping for QoS tests.

Wire format is JSON lines: request {v, type, id, seq, ts_ns}; response echoes
id, seq and ts_ns and adds server_ts_ns. Output is JSONL for easy parsing.
"""
import argparse, json, socket, sys, time, signal

STOP = False
def stop_handler(signum, frame):
    global STOP
    STOP = True

def wire(obj):
    return (json.dumps(obj, separators=(",", ":")) + "\n").encode()

def timestamp():
    return time.strftime("%H:%M:%S") + f".{time.time_ns() // 1_000_000 % 1000:03d}"

def server(args):
    s = socket.socket(socket.AF_INET6 if ":" in args.bind else socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((args.bind, args.port))
    print(json.dumps({"event":"ready", "bind":args.bind, "port":args.port}), flush=True)
    while True:
        data, peer = s.recvfrom(args.max_packet)
        now = time.monotonic_ns()
        try: req = json.loads(data.split(b"\n", 1)[0])
        except (ValueError, UnicodeDecodeError): continue
        if req.get("type") != "udp_ping" or req.get("v") != 1: continue
        resp = {"v":1,"type":"udp_pong","id":req.get("id"),"seq":req.get("seq"),
                "ts_ns":req.get("ts_ns"),"server_ts_ns":now}
        s.sendto(wire(resp), peer)

def client(args):
    global STOP
    STOP = False
    signal.signal(signal.SIGINT, stop_handler)
    family = socket.AF_INET6 if args.ipv6 or (not args.ipv4 and ":" in args.host) else socket.AF_INET
    s = socket.socket(family, socket.SOCK_DGRAM); s.settimeout(args.timeout)
    ident = args.id or str(time.time_ns())
    interval = args.interval if args.interval is not None else 1.0 / args.pps
    sent = time.monotonic(); seq = 0; received = 0; rtts = []; started = time.monotonic()
    print(f"[{timestamp()}] UDP PING {args.host}:{args.port} ({args.size} bytes of data)", flush=True)
    while not STOP and (args.count is None or seq < args.count):
        target = sent + seq * interval
        delay = target - time.monotonic()
        if delay > 0: time.sleep(delay)
        seq += 1; ts = time.monotonic_ns()
        packet = wire({"v":1,"type":"udp_ping","id":ident,"seq":seq,"ts_ns":ts})
        packet += b"x" * max(0, args.size - len(packet)); s.sendto(packet, (args.host,args.port))
        result = {"event":"probe","id":ident,"seq":seq,"sent_ts_ns":ts}
        try:
            data, _ = s.recvfrom(args.max_packet); recv = time.monotonic_ns(); pong=json.loads(data)
            result.update(received_ts_ns=recv, rtt_us=(recv-ts)/1000, response=pong,
                          valid=(pong.get("type")=="udp_pong" and pong.get("id")==ident and pong.get("seq")==seq))
            received += int(result["valid"])
            if result["valid"]: rtts.append(result["rtt_us"] / 1000)
        except socket.timeout:
            result.update(timeout=True, valid=False)
        if not args.quiet:
            if args.json: print(json.dumps(result, separators=(",", ":")), flush=True)
            elif result.get("valid"): print(f"[{timestamp()}] {args.size} bytes from {args.host}: udp_seq={seq} time={result['rtt_us']/1000:.3f} ms", flush=True)
            else: print(f"[{timestamp()}] From {args.host}: udp_seq={seq} timeout", flush=True)
    elapsed = (time.monotonic() - started) * 1000
    loss = (seq-received)/seq*100 if seq else 0
    print(f"\n--- {args.host} udp ping statistics ---\n{seq} packets transmitted, {received} received, {loss:.1f}% packet loss, time {elapsed:.0f}ms", flush=True)
    if rtts:
        avg=sum(rtts)/len(rtts); variance=sum((x-avg)**2 for x in rtts)/len(rtts)
        print(f"rtt min/avg/max/mdev = {min(rtts):.3f}/{avg:.3f}/{max(rtts):.3f}/{variance**0.5:.3f} ms", flush=True)
    s.close()

def main():
    p=argparse.ArgumentParser(); sub=p.add_subparsers(dest="mode", required=True)
    sv=sub.add_parser("server"); sv.add_argument("--bind",default="0.0.0.0"); sv.add_argument("--port",type=int,default=11111); sv.add_argument("--max-packet",type=int,default=4096); sv.set_defaults(func=server)
    c=sub.add_parser("client"); c.add_argument("host"); c.add_argument("-c","--count",type=int); c.add_argument("-i","--interval",type=float); c.add_argument("--pps",type=float,default=1,help="packets per second (default: 1); -i takes precedence"); c.add_argument("-W","--timeout",type=float,default=1); c.add_argument("-s","--size",type=int,default=64); c.add_argument("-q","--quiet",action="store_true"); c.add_argument("--json",action="store_true",help="emit JSONL probe records"); c.add_argument("-4","--ipv4",action="store_true"); c.add_argument("-6","--ipv6",action="store_true"); c.add_argument("--port",type=int,default=11111); c.add_argument("--id"); c.add_argument("--max-packet",type=int,default=4096); c.set_defaults(func=client)
    a=p.parse_args(); a.func(a)
if __name__ == "__main__": main()
