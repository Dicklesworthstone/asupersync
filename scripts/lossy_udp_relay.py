#!/usr/bin/env python3
"""lossy_udp_relay.py — a tiny userspace lossy UDP relay for ATP convergence e2e tests.

Sits between an ATP sender and receiver and forwards datagrams while dropping a
controlled fraction of them, so we can test RaptorQ erasure repair + fountain
feedback (NeedMore rounds) at a known packet-loss epsilon WITHOUT touching the
runtime source, without root/CAP_NET_ADMIN, and without globally degrading the
loopback interface for other agents (which `tc qdisc ... dev lo` would do).

Topology:
    sender --(send to LISTEN)-->  [relay]  --(forward to TARGET)--> receiver
    sender <--(forward back)----  [relay]  <--(replies)----------- receiver

Loss is directional so we can isolate "does fountain coding repair DATA loss"
from "does the CONTROL plane survive loss" (the F6 concern):
    --loss       drop probability for DATA   (sender -> target), default 0.0
    --loss-ctrl  drop probability for CONTROL (target -> sender), default 0.0

Loss is reproducible: a seeded PRNG per direction (--seed), so a failing epsilon
can be replayed exactly. QUIC keys its connection on the DCID, not the strict
4-tuple, so the receiver tolerates seeing all packets from the relay's address
(no path migration on loopback).

Usage:
    lossy_udp_relay.py --listen 127.0.0.1:19700 --target 127.0.0.1:19701 \
        --loss 0.05 [--loss-ctrl 0.0] [--seed 1] [--ready-file /tmp/r.ready]

    # 10 mbit/s sender->receiver cap, without touching loopback qdisc:
    lossy_udp_relay.py --listen 127.0.0.1:19700 --target 127.0.0.1:19701 \
        --loss 0.10 --delay-ms 200 --mbit 10 --rate-max-queue-ms 300

Prints a one-line JSON stats summary to stdout on clean shutdown (SIGTERM/SIGINT)
and periodically to stderr. Exit 0 on clean shutdown.
"""
import argparse
import json
import os
import random
import select
import signal
import socket
import sys
import time


def parse_addr(s: str):
    host, _, port = s.rpartition(":")
    return (host, int(port))


def mbit_to_bytes_per_sec(mbit: float) -> int:
    if mbit <= 0.0:
        return 0
    return max(1, int((mbit * 1_000_000.0) / 8.0))


class RateLimiter:
    def __init__(self, bytes_per_sec: int, burst_bytes: int, max_queue_ms: int):
        self.bytes_per_sec = max(0, int(bytes_per_sec))
        self.burst_bytes = max(1, int(burst_bytes))
        self.max_queue_s = max(0.0, float(max_queue_ms) / 1000.0)
        self.next_send_at = 0.0

    def schedule(self, now: float, size: int):
        if self.bytes_per_sec <= 0:
            return now
        burst_window = self.burst_bytes / float(self.bytes_per_sec)
        self.next_send_at = max(self.next_send_at, now - burst_window)
        due = max(now, self.next_send_at)
        if due - now > self.max_queue_s:
            return None
        self.next_send_at = due + max(1, size) / float(self.bytes_per_sec)
        return due


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", required=True, help="HOST:PORT the sender targets")
    ap.add_argument("--target", required=True, help="HOST:PORT of the real receiver")
    ap.add_argument("--loss", type=float, default=0.0, help="drop prob, data dir (sender->target)")
    ap.add_argument("--loss-ctrl", type=float, default=0.0, help="drop prob, ctrl dir (target->sender)")
    ap.add_argument("--delay-ms", type=float, default=0.0, help="base one-way delay for data packets")
    ap.add_argument("--delay-ctrl-ms", type=float, default=0.0, help="base one-way delay for control packets")
    ap.add_argument("--mbit", type=float, default=0.0,
                    help="sender->target rate cap in decimal megabits/sec; 10 means 1.25 MB/s")
    ap.add_argument("--mbit-ctrl", type=float, default=0.0,
                    help="target->sender rate cap in decimal megabits/sec")
    ap.add_argument("--rate-bytes-per-sec", type=int, default=0,
                    help="sender->target rate cap in bytes/sec; overrides --mbit when nonzero")
    ap.add_argument("--rate-ctrl-bytes-per-sec", type=int, default=0,
                    help="target->sender rate cap in bytes/sec; overrides --mbit-ctrl when nonzero")
    ap.add_argument("--rate-burst-bytes", type=int, default=16 * 1024,
                    help="token-bucket burst size for rate-capped directions")
    ap.add_argument("--rate-max-queue-ms", type=int, default=300,
                    help="drop a datagram when rate shaping would queue it longer than this")
    ap.add_argument("--loss-scope", choices=["1rtt", "all"], default="1rtt",
                    help="which sender->target packets are drop-eligible: '1rtt' = only QUIC short-header "
                         "(1-RTT app data) packets, never the handshake (default — isolates data-plane "
                         "convergence from handshake-retransmission fragility); 'all' = any datagram")
    ap.add_argument("--seed", type=int, default=1, help="PRNG seed (reproducible loss)")
    ap.add_argument("--ready-file", default="", help="touch this path once bound (readiness signal)")
    ap.add_argument("--stats-file", default="", help="write final JSON stats here too")
    args = ap.parse_args()

    listen = parse_addr(args.listen)
    target = parse_addr(args.target)
    data_rate = args.rate_bytes_per_sec or mbit_to_bytes_per_sec(args.mbit)
    ctrl_rate = args.rate_ctrl_bytes_per_sec or mbit_to_bytes_per_sec(args.mbit_ctrl)
    data_limiter = RateLimiter(data_rate, args.rate_burst_bytes, args.rate_max_queue_ms)
    ctrl_limiter = RateLimiter(ctrl_rate, args.rate_burst_bytes, args.rate_max_queue_ms)

    # one socket faces the sender (bound to LISTEN), one faces the receiver (ephemeral).
    s_in = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s_in.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s_in.bind(listen)
    s_out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s_out.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 22)
    s_in.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 22)

    rng_data = random.Random(args.seed)
    rng_ctrl = random.Random(args.seed ^ 0x5DEECE66D)
    sender_addr = None  # learned from the first inbound datagram

    stats = {
        "listen": args.listen, "target": args.target, "loss": args.loss,
        "loss_ctrl": args.loss_ctrl, "seed": args.seed,
        "loss_scope": args.loss_scope,
        "delay_ms": args.delay_ms, "delay_ctrl_ms": args.delay_ctrl_ms,
        "rate_bytes_per_sec": data_rate, "rate_ctrl_bytes_per_sec": ctrl_rate,
        "rate_burst_bytes": args.rate_burst_bytes, "rate_max_queue_ms": args.rate_max_queue_ms,
        "data_fwd": 0, "data_drop": 0, "data_bytes": 0,
        "data_rate_drop": 0, "data_rate_delay": 0,
        "handshake_fwd": 0,  # long-header (Initial/Handshake/0-RTT) pkts, sender->target, never dropped under 1rtt scope
        "ctrl_fwd": 0, "ctrl_drop": 0, "ctrl_bytes": 0,
        "ctrl_rate_drop": 0, "ctrl_rate_delay": 0,
    }
    pending = []

    running = {"v": True}

    def emit_stats():
        out = dict(stats)
        d = out["data_fwd"] + out["data_drop"]
        c = out["ctrl_fwd"] + out["ctrl_drop"]
        out["data_actual_loss"] = round(out["data_drop"] / d, 4) if d else 0.0
        out["ctrl_actual_loss"] = round(out["ctrl_drop"] / c, 4) if c else 0.0
        line = json.dumps(out)
        sys.stdout.write(line + "\n")
        sys.stdout.flush()
        if args.stats_file:
            try:
                with open(args.stats_file, "w") as f:
                    f.write(line + "\n")
            except OSError:
                pass

    def on_signal(_signum, _frame):
        running["v"] = False

    def queue_or_send(sock, payload, addr, limiter, delay_ms, fwd_key, bytes_key, rate_drop_key, rate_delay_key):
        now = time.time()
        due = limiter.schedule(now, len(payload))
        if due is None:
            stats[rate_drop_key] += 1
            return
        due += max(0.0, float(delay_ms) / 1000.0)
        if due > now:
            pending.append((due, sock, payload, addr, fwd_key, bytes_key))
            stats[rate_delay_key] += 1
            return
        try:
            sock.sendto(payload, addr)
            stats[fwd_key] += 1
            stats[bytes_key] += len(payload)
        except OSError:
            pass

    def flush_pending():
        now = time.time()
        kept = []
        for due, sock, payload, addr, fwd_key, bytes_key in pending:
            if due > now:
                kept.append((due, sock, payload, addr, fwd_key, bytes_key))
                continue
            try:
                sock.sendto(payload, addr)
                stats[fwd_key] += 1
                stats[bytes_key] += len(payload)
            except OSError:
                pass
        pending[:] = kept

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)

    if args.ready_file:
        try:
            with open(args.ready_file, "w") as f:
                f.write("ready\n")
        except OSError:
            pass
    sys.stderr.write(
        f"relay listening {args.listen} -> {args.target} loss={args.loss} ctrl={args.loss_ctrl} "
        f"rate_Bps={data_rate} ctrl_rate_Bps={ctrl_rate}\n"
    )
    sys.stderr.flush()

    last_stats = time.time()
    while running["v"]:
        flush_pending()
        try:
            ready, _, _ = select.select([s_in, s_out], [], [], 0.05 if pending else 0.5)
        except (InterruptedError, OSError):
            break
        for sock in ready:
            try:
                data, addr = sock.recvfrom(65535)
            except (BlockingIOError, InterruptedError):
                continue
            except OSError:
                continue
            if sock is s_in:
                # sender -> target (DATA direction)
                sender_addr = addr
                # QUIC long header (Initial/Handshake/0-RTT) has the high bit 0x80 set in byte 0;
                # 1-RTT app-data uses a short header (0x80 clear). Under the default '1rtt' scope we
                # never drop handshake packets, so a single lost handshake packet (which today's stack
                # cannot retransmit) does not masquerade as a data-plane convergence failure.
                is_long_header = bool(data) and (data[0] & 0x80) != 0
                if is_long_header:
                    stats["handshake_fwd"] += 1
                drop_eligible = args.loss_scope == "all" or not is_long_header
                if args.loss > 0.0 and drop_eligible and rng_data.random() < args.loss:
                    stats["data_drop"] += 1
                    continue
                if drop_eligible:
                    queue_or_send(
                        s_out, data, target, data_limiter, args.delay_ms,
                        "data_fwd", "data_bytes", "data_rate_drop", "data_rate_delay",
                    )
                else:
                    queue_or_send(
                        s_out, data, target, RateLimiter(0, 1, 0), 0,
                        "data_fwd", "data_bytes", "data_rate_drop", "data_rate_delay",
                    )
            else:
                # target -> sender (CONTROL/feedback direction)
                if sender_addr is None:
                    continue  # nobody to forward to yet
                if args.loss_ctrl > 0.0 and rng_ctrl.random() < args.loss_ctrl:
                    stats["ctrl_drop"] += 1
                    continue
                queue_or_send(
                    s_in, data, sender_addr, ctrl_limiter, args.delay_ctrl_ms,
                    "ctrl_fwd", "ctrl_bytes", "ctrl_rate_drop", "ctrl_rate_delay",
                )
        flush_pending()
        now = time.time()
        if now - last_stats >= 5.0:
            sys.stderr.write(
                f"relay stats data fwd={stats['data_fwd']} drop={stats['data_drop']} "
                f"rate_drop={stats['data_rate_drop']} ctrl fwd={stats['ctrl_fwd']} "
                f"drop={stats['ctrl_drop']} ctrl_rate_drop={stats['ctrl_rate_drop']}\n")
            sys.stderr.flush()
            last_stats = now

    flush_pending()
    emit_stats()
    return 0


if __name__ == "__main__":
    sys.exit(main())
