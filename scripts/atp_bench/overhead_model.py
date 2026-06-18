#!/usr/bin/env python3
"""Per-packet / syscall overhead model for the ATP vs rsync matrix.

Consumes the matrix JSONL (the rows `run_matrix_cell.sh` emits, which now carry
`est_min_datagrams` and `sender_ctx_switches`) and answers the perfect-link
question the BENCHMARK INTEGRITY STANDARD raised: *why does atp lose on a clean,
rate-capped, low-latency link?* The hypothesis is per-packet syscall overhead —
atp sprays ~one `sendto` per ~1.2 KB symbol while rsync streams a few large TCP
writes. This script quantifies it from real data and projects the GSO/sendmmsg
(E-6.x) payoff so the swarm can decide if that lever is worth it.

For each low-loss regime (`perfect`, `good`) and each atp method it reports, per
verified cell:
  * achieved throughput vs the link rate  → **link utilization** (low ⇒ not
    bandwidth-bound on a clean link);
  * `sendto`/s (= est_min_datagrams / wall) and **µs per datagram** (an upper
    bound on per-packet cost — wall also includes RTT/decode);
  * **projected GSO speedup**: batching `G` segments per syscall cuts the syscall
    count ~G×, so a syscall-bound transfer's wall shrinks toward bandwidth-bound.

A cell is classified overhead-bound (utilization < `--util-bound`, default 0.6) vs
bandwidth-bound. Only sha-verified, non-timed-out rows are admitted.

Usage: overhead_model.py results.jsonl [more.jsonl ...] [--gso 8] [--util-bound 0.6]
"""

from __future__ import annotations

import argparse
import json
import math
import statistics
import sys
from collections import defaultdict

# Regimes where loss is negligible, so a slowdown is overhead, not repair.
LOW_LOSS_REGIMES = {"perfect", "good"}


def parse_rate_bytes_per_s(rate: str | None) -> float | None:
    """Parse a netem rate string ('1gbit', '50mbit', '200kbit') to bytes/s."""
    if not rate:
        return None
    r = str(rate).strip().lower()
    mult = 1.0
    for suffix, m in (("gbit", 1e9), ("mbit", 1e6), ("kbit", 1e3), ("bit", 1.0)):
        if r.endswith(suffix):
            try:
                return float(r[: -len(suffix)]) * m / 8.0  # bits/s → bytes/s
            except ValueError:
                return None
    try:
        return float(r) / 8.0
    except ValueError:
        return None
    return mult


def is_atp(method: str) -> bool:
    return method.lower().startswith("atp") or "atp" in method.lower()


def load_rows(paths: list[str]) -> list[dict]:
    rows: list[dict] = []
    for p in paths:
        with open(p, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        rows.append(json.loads(line))
                    except ValueError:
                        print(f"warn: bad JSONL line in {p}", file=sys.stderr)
    return rows


def verified(r: dict) -> bool:
    return bool(r.get("sha_ok")) and not r.get("timed_out") and str(r.get("status", "ok")).lower() == "ok"


def median(xs: list[float]) -> float | None:
    xs = [x for x in xs if x is not None]
    return statistics.median(xs) if xs else None


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="ATP per-packet overhead model → markdown.")
    ap.add_argument("jsonl", nargs="+", help="matrix results JSONL")
    ap.add_argument("--gso", type=int, default=8, help="segments per GSO/sendmmsg syscall to project")
    ap.add_argument("--util-bound", type=float, default=0.6, help="below this link-util ⇒ overhead-bound")
    args = ap.parse_args(argv)

    rows = [r for r in load_rows(args.jsonl) if is_atp(r.get("method", "")) and verified(r)]
    if not rows:
        print("# ATP overhead model\n\nNo verified atp rows found.", file=sys.stdout)
        return 0

    # cell -> list of rows (reps)
    cells: dict[tuple, list[dict]] = defaultdict(list)
    for r in rows:
        if r.get("regime") in LOW_LOSS_REGIMES and (r.get("est_min_datagrams") or 0) > 0 and (r.get("wall_s") or 0) > 0:
            cells[(r["method"], r["regime"], r["workload"])].append(r)

    out: list[str] = []
    out.append("# ATP per-packet / syscall overhead model\n")
    out.append("Low-loss regimes only (`perfect`, `good`) so slowdown is overhead, not repair. "
               "Verified rows only. `µs/dgram` is an upper bound (wall includes RTT/decode). "
               f"GSO projection batches **{args.gso}** segments per syscall.\n")
    out.append("| method | regime | workload | size | wall s | MB/s | link MB/s | util | sendto/s | µs/dgram | ctx/MB | bound | GSO→ |")
    out.append("|---|---|---|--:|--:|--:|--:|--:|--:|--:|--:|---|--:|")

    overhead_cells = 0
    total_cells = 0
    for key in sorted(cells):
        method, regime, workload = key
        reps = cells[key]
        size = median([r.get("size_bytes") for r in reps]) or 0
        wall = median([r.get("wall_s") for r in reps])
        dgrams = median([r.get("est_min_datagrams") for r in reps]) or 0
        ctx = median([r.get("sender_ctx_switches") for r in reps])
        rate_bps = parse_rate_bytes_per_s((reps[0].get("netem") or {}).get("rate"))
        if not wall or wall <= 0:
            continue
        total_cells += 1
        mbps = size / wall / 1e6
        link_mbps = rate_bps / 1e6 if rate_bps else None
        util = (mbps * 1e6 / rate_bps) if rate_bps else None
        sendto_s = dgrams / wall
        us_per_dgram = wall * 1e6 / dgrams if dgrams else None
        ctx_per_mb = (ctx / (size / 1e6)) if (ctx is not None and size > 0) else None
        bound = "?" if util is None else ("overhead" if util < args.util_bound else "bandwidth")
        if bound == "overhead":
            overhead_cells += 1
        # If syscall-bound, batching G/syscall cuts syscalls ~G× → wall toward
        # bandwidth-bound. Projected best-case util ≈ min(1.0, util * G).
        gso_util = None if util is None else min(1.0, util * args.gso)
        out.append(
            f"| {method} | {regime} | {workload} | {size/1e6:.0f}MB | {wall:.2f} | {mbps:.1f} | "
            f"{('%.0f' % link_mbps) if link_mbps else '—'} | "
            f"{('%.0f%%' % (util*100)) if util is not None else '—'} | "
            f"{sendto_s:,.0f} | {('%.2f' % us_per_dgram) if us_per_dgram else '—'} | "
            f"{('%.0f' % ctx_per_mb) if ctx_per_mb is not None else '—'} | {bound} | "
            f"{('%.0f%% util' % (gso_util*100)) if gso_util is not None else '—'} |"
        )

    out.append("")
    out.append("## Verdict\n")
    if total_cells:
        frac = overhead_cells / total_cells
        out.append(f"- {overhead_cells}/{total_cells} low-loss cells are **overhead-bound** "
                   f"(link util < {args.util_bound:.0%}).")
        if frac >= 0.5:
            out.append(f"- atp is **syscall/per-packet-bound** on clean links ⇒ GSO/sendmmsg "
                       f"(E-6.x) batching ~{args.gso}/syscall is the right lever; projected util "
                       f"gains are in the `GSO→` column (capped at 100% = bandwidth-bound).")
        else:
            out.append("- atp is mostly **bandwidth-bound** on clean links ⇒ per-packet syscall "
                       "overhead is NOT the dominant cost here; look elsewhere (decode, pacing).")
    else:
        out.append("- No low-loss atp cells with packet counts to model.")
    out.append("\n_Note: `µs/dgram` and `sendto/s` are wall-derived upper bounds; a `perf stat -e "
               "'syscalls:sys_enter_sendto'` run confirms the true syscall count. The model isolates "
               "the per-packet floor that GSO/sendmmsg removes._")

    print("\n".join(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
