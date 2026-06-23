#!/usr/bin/env python3
"""ATP-RQ per-round trace gate: detect the LEVER-1 pacing-collapse failure modes.

SapphireHill's LEVER-1 PASS criteria are checked by hand every bench iteration
(ledger MATRIX-8/9): a candidate is good only if the `sender: NeedMore` per-round
trace (ATP_RQ_TRACE=1) shows NO path-rate collapse and source-resend rounds
deliver received≈sent. This automates that read into a deterministic gate so a
regression (v2 estimator-collapse, v3 frame-break) is caught mechanically.

Feed it the captured ATP_RQ_TRACE sender log (file arg or stdin). It parses each
`round=N ...` line as loose `key=value` pairs (tolerant of field churn across
versions), normalizes rate units (`106M`/`58Mbit`/`path_rate_bps=...`), and flags:

  1. PATH-RATE COLLAPSE — rate falls > --collapse-factor below the round-1 rate
     while `pending` persists (the MATRIX-8 106M→8.6M death spiral). The pacing
     estimator must not self-throttle on a slow-to-decode block.
  2. SOURCE-RESEND UNDER-CREDIT — a round whose sent ≫ received (received <
     --credit-min × sent) on a low-loss run: the re-sent source wasn't credited
     in-round (BUG 1), which poisons the wire-loss estimate.
  3. LOSS-BAR INFLATION — loss_bar/repair_loss_bar climbs > --loss-inflate above
     its round-1 value while real wire loss is mild (the decode-pending pressure
     leaking into the pacing loss).

Exit non-zero on any flagged round (CI/bench gate). Loss-regime traces legitimately
carry nonzero loss; pass --wire-loss to set the regime's true loss so inflation is
judged against it, and --min-rounds to ignore single-round runs.

Usage: rq_trace_collapse_check.py send.log [--collapse-factor 2.0] [--credit-min 0.5]
"""

from __future__ import annotations

import argparse
import re
import sys

ROUND_RE = re.compile(r"\bround\s*=\s*(\d+)")
KV_RE = re.compile(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*([^\s,]+)")

# Field aliases (trace wording has drifted across LEVER-1 versions).
RATE_KEYS = ("rate", "path_rate_bps", "path_rate", "pacing_rate_bps")
SENT_KEYS = ("sent_this_round", "sent")
RECV_KEYS = ("received_this_round", "received", "round_symbols_observed")
LOSS_KEYS = ("loss_bar", "repair_loss_bar", "pacing_loss_bar")
PENDING_KEYS = ("pending",)


def parse_rate_bps(raw: str) -> float | None:
    """Parse a rate token to bits/s: '106M'/'58Mbit'/'8.6M'/'112000000'."""
    s = raw.strip().lower().rstrip("/s")
    m = re.match(r"^([0-9]*\.?[0-9]+)\s*([kmg]?)(bit|bps|b)?$", s)
    if not m:
        return None
    val = float(m.group(1))
    mult = {"": 1.0, "k": 1e3, "m": 1e6, "g": 1e9}[m.group(2)]
    return val * mult


def first_present(kv: dict, keys, parse=float):
    for k in keys:
        if k in kv:
            try:
                return parse(kv[k])
            except (TypeError, ValueError):
                return None
    return None


def parse_rounds(lines) -> list[dict]:
    rounds = []
    for line in lines:
        if not ROUND_RE.search(line):
            continue
        kv = {k: v for k, v in KV_RE.findall(line)}
        r = {
            "round": int(ROUND_RE.search(line).group(1)),
            "rate_bps": first_present(kv, RATE_KEYS, parse_rate_bps),
            "sent": first_present(kv, SENT_KEYS, lambda x: float(x)),
            "received": first_present(kv, RECV_KEYS, lambda x: float(x)),
            "loss_bar": first_present(kv, LOSS_KEYS, float),
            "pending": first_present(kv, PENDING_KEYS, float),
            "source_resend": "source_resend" in line or "source_request" in line.lower(),
        }
        rounds.append(r)
    return rounds


# Receiver work stages (cc_2 R1, 317hxr.29): the `receiver: ... ObjectComplete`
# trace splits per-datagram intake and deferred decode into these timers
# (MATRIX-23 pinpointed feed_micros as the clean-link wall; later large-lossy
# profiling needs decode_micros to distinguish feed serialization from RaptorQ solve).
RECEIVER_STAGE_KEYS = (
    "feed_micros",
    "decode_micros",
    "recv_micros",
    "drain_micros",
    "parse_micros",
)


def parse_receiver_intake(lines) -> list[dict]:
    records = []
    for line in lines:
        if not any(
            key in line for key in ("intake_bytes_per_s", "feed_micros", "decode_micros")
        ):
            continue
        kv = {k: v for k, v in KV_RE.findall(line)}
        stages = {
            k: v for k in RECEIVER_STAGE_KEYS if (v := first_present(kv, (k,))) is not None
        }
        if not stages:
            continue
        records.append({"stages": stages, "intake_bytes_per_s": first_present(kv, ("intake_bytes_per_s",))})
    return records


def report_receiver_intake(records, target_mbps) -> list[str]:
    """Print the receiver-stage bottleneck breakdown (which stage caps throughput);
    return flags. Auto-identifies the dominant stage = SapphireHill's 'attack the top item'."""
    if not records:
        return []
    agg = {k: 0.0 for k in RECEIVER_STAGE_KEYS}
    rates = []
    for rec in records:
        for k, v in rec["stages"].items():
            agg[k] += v
        if rec["intake_bytes_per_s"]:
            rates.append(rec["intake_bytes_per_s"])
    total = sum(agg.values()) or 1.0
    dominant = max(agg, key=lambda k: agg[k])
    print("\n## Receiver-stage bottleneck (cc_2 R1 trace)\n")
    print("| stage | micros | % of receiver work |")
    print("|--|--:|--:|")
    for k in RECEIVER_STAGE_KEYS:
        mark = "  ← WALL" if k == dominant else ""
        print(f"| {k} | {agg[k]:.0f} | {100.0 * agg[k] / total:.2f}%{mark} |")
    flags = []
    suffix = ""
    if rates:
        mbps = (sum(rates) / len(rates)) / 1e6
        suffix = f"mean intake = {mbps:.1f} MB/s; "
        if target_mbps is not None and mbps < target_mbps:
            flags.append(f"receiver intake {mbps:.1f} MB/s < target {target_mbps} MB/s (bottleneck: {dominant})")
    print(f"\n- {suffix}dominant receiver stage = **{dominant}** "
          f"({100.0 * agg[dominant] / total:.1f}%) → attack this")
    return flags


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="ATP-RQ trace pacing-collapse gate.")
    ap.add_argument("log", nargs="?", help="ATP_RQ_TRACE sender log (default: stdin)")
    ap.add_argument("--collapse-factor", type=float, default=2.0,
                    help="flag if rate falls below round-1 rate / this while pending persists")
    ap.add_argument("--credit-min", type=float, default=0.5,
                    help="flag a source-resend round if received < this × sent")
    ap.add_argument("--loss-inflate", type=float, default=3.0,
                    help="flag if loss_bar climbs above round-1 loss_bar × this")
    ap.add_argument("--wire-loss", type=float, default=None,
                    help="regime's true wire loss fraction (for inflation judgment)")
    ap.add_argument("--min-rounds", type=int, default=2)
    ap.add_argument("--max-rounds", type=int, default=None,
                    help="FAIL if convergence took more feedback rounds than this "
                         "(MATRIX-20 lossy wall = feedback rounds; LEVER-B/F target fr<=2). "
                         "Off by default so non-lossy traces aren't flagged.")
    ap.add_argument("--receiver-target-mbps", type=float, default=None,
                    help="FAIL if mean receiver intake_bytes_per_s < this MB/s "
                         "(MATRIX-24 goal: intake >> rsync's ~40 MB/s). Off by default.")
    args = ap.parse_args(argv)

    src = open(args.log, encoding="utf-8") if args.log else sys.stdin
    lines = list(src)
    if args.log:
        src.close()
    rounds = parse_rounds(lines)
    recv_records = parse_receiver_intake(lines)

    flags: list[str] = []
    print("# ATP-RQ trace pacing-collapse gate\n")
    print("| round | rate(bps) | sent | recv | recv/sent | loss_bar | pending | src-resend |")
    print("|--:|--:|--:|--:|--:|--:|--:|:--:|")
    rate0 = next((r["rate_bps"] for r in rounds if r["rate_bps"]), None)
    loss0 = next((r["loss_bar"] for r in rounds if r["loss_bar"] is not None), None)
    for r in rounds:
        ratio = (r["received"] / r["sent"]) if (r["received"] is not None and r["sent"]) else None
        print("| {} | {} | {} | {} | {} | {} | {} | {} |".format(
            r["round"],
            f"{r['rate_bps']:.3g}" if r["rate_bps"] else "—",
            f"{r['sent']:.0f}" if r["sent"] is not None else "—",
            f"{r['received']:.0f}" if r["received"] is not None else "—",
            f"{ratio:.2f}" if ratio is not None else "—",
            f"{r['loss_bar']:.3f}" if r["loss_bar"] is not None else "—",
            f"{r['pending']:.0f}" if r["pending"] is not None else "—",
            "yes" if r["source_resend"] else ""))
        # 1. path-rate collapse while pending persists
        if rate0 and r["rate_bps"] and r["pending"] and r["pending"] > 0:
            if r["rate_bps"] < rate0 / args.collapse_factor:
                flags.append(f"round {r['round']}: path-rate collapse "
                             f"{r['rate_bps']:.3g} < round-1 {rate0:.3g}/{args.collapse_factor} (pending={r['pending']:.0f})")
        # 2. source-resend under-credit
        if r["source_resend"] and r["sent"] and r["received"] is not None:
            if r["received"] < args.credit_min * r["sent"]:
                flags.append(f"round {r['round']}: source-resend under-credit "
                             f"received={r['received']:.0f} < {args.credit_min}×sent({r['sent']:.0f})")
        # 3. loss_bar inflation beyond the real wire loss
        if loss0 is not None and r["loss_bar"] is not None and loss0 > 0:
            base = max(loss0, args.wire_loss or 0.0)
            if r["loss_bar"] > base * args.loss_inflate:
                flags.append(f"round {r['round']}: loss_bar inflated "
                             f"{r['loss_bar']:.3f} > {base:.3f}×{args.loss_inflate}")

    # 4. feedback-rounds budget — MATRIX-20 proved the lossy wall IS the feedback
    #    rounds (50M/bad fr=4 ≈ 4×80ms RTT + re-spray). LEVER-B/F must cut them.
    max_round = max((r["round"] for r in rounds), default=0)
    if args.max_rounds is not None and max_round > args.max_rounds:
        flags.append(f"convergence took {max_round} feedback rounds > budget "
                     f"{args.max_rounds} (MATRIX-20 lossy wall; LEVER-B/F must cut rounds)")

    flags += report_receiver_intake(recv_records, args.receiver_target_mbps)

    print("\n## Verdict\n")
    print(f"- parsed {len(rounds)} round record(s); highest feedback round = {max_round}; "
          f"{len(recv_records)} receiver-stage record(s).")
    if len(rounds) < args.min_rounds and not flags:
        print(f"- only {len(rounds)} round(s) parsed (need ≥{args.min_rounds}); not a collapse sample.")
        return 0
    if flags:
        print("PACING-COLLAPSE GATE **FAIL** — LEVER-1 candidate regresses:")
        for f in flags:
            print(f"- ❌ {f}")
        return 1
    print("GATE PASS — no path-rate collapse, source-resend credited in-round, loss_bar stable.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
