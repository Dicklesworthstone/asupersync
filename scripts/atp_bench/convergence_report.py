#!/usr/bin/env python3
"""ATP-RQ lossy-convergence report from the matrix JSONL.

The B-8/E-7 critical lever is that source-first + the K-aware FEC fallback
(bead 317hxr.6.1.1: fallback must engage in repair-only rounds, not self-disable)
CONVERGES under loss in a bounded number of feedback rounds — the 50M@3%/50ms
cell must go from "123s + sha MISS" to "converges, sha OK, few rounds". This
script verifies that from real run data, independently of the wall/RSS scorecard:

For each (regime, workload) it reports, over atp-rq reps:
  * convergence rate = fraction of reps that verified (sha_ok, not timed out,
    status ok) — MUST be 1.0 under loss for a fail-closed transport that beats
    rsync on lossy links;
  * median / max feedback_rounds — the FEC fallback working means rounds stay
    bounded and do NOT grow pathologically with loss;
  * a GATE: a cell FAILS if any rep did not converge, or if median rounds exceed
    --max-rounds (default 16, the DEFAULT_MAX_FEEDBACK_ROUNDS fail-closed bound).

This is the empirical check for the 6.1.1 fix: before the fix the high-loss large
cell never converged (rounds hit the cap → NoConvergence → sha MISS); after, it
converges with rounds well under the cap.

Usage: convergence_report.py results.jsonl [more.jsonl ...] [--max-rounds 16]
Exit non-zero if any atp-rq cell fails the convergence gate (CI-friendly).
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from collections import defaultdict


def is_atp_rq(method: str) -> bool:
    m = method.lower()
    return m.startswith("atp-rq") or (m.startswith("atp") and "quic" not in m)


def load_rows(paths: list[str]) -> list[dict]:
    rows: list[dict] = []
    for p in paths:
        with open(p, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    print(f"warn: bad JSONL line in {p}", file=sys.stderr)
    return rows


def converged(r: dict) -> bool:
    return (
        bool(r.get("sha_ok"))
        and not r.get("timed_out")
        and str(r.get("status", "ok")).lower() == "ok"
    )


def num(v, default=None):
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="ATP-RQ lossy-convergence report → markdown + gate.")
    ap.add_argument("jsonl", nargs="+", help="matrix results JSONL")
    ap.add_argument("--max-rounds", type=float, default=16.0,
                    help="median feedback_rounds above this fails the gate (DEFAULT_MAX_FEEDBACK_ROUNDS)")
    args = ap.parse_args(argv)

    rows = [r for r in load_rows(args.jsonl) if is_atp_rq(str(r.get("method", "")))]
    cells: dict[tuple, list[dict]] = defaultdict(list)
    for r in rows:
        cells[(str(r.get("regime")), str(r.get("workload")))].append(r)

    out: list[str] = []
    out.append("# ATP-RQ lossy convergence report\n")
    out.append("Verifies source-first + FEC fallback (bead 317hxr.6.1.1) converges under loss in "
               f"bounded rounds. Gate: every rep converges AND median feedback_rounds ≤ {args.max_rounds:.0f}.\n")
    out.append("| regime | workload | reps | converged | conv-rate | median rounds | max rounds | gate |")
    out.append("|---|---|--:|--:|--:|--:|--:|---|")

    failures: list[str] = []
    if not cells:
        out.append("| — | — | 0 | 0 | — | — | — | — |")
    for (regime, workload) in sorted(cells):
        reps = cells[(regime, workload)]
        n = len(reps)
        ok = [r for r in reps if converged(r)]
        conv_rate = len(ok) / n if n else 0.0
        rounds = [num(r.get("feedback_rounds")) for r in ok]
        rounds = [x for x in rounds if x is not None]
        med = statistics.median(rounds) if rounds else None
        mx = max(rounds) if rounds else None
        gate_ok = (len(ok) == n) and (med is not None and med <= args.max_rounds)
        # A regime with no loss is allowed 0 rounds; the gate still requires full convergence.
        gate = "PASS" if gate_ok else "FAIL"
        if not gate_ok:
            why = []
            if len(ok) != n:
                why.append(f"{n - len(ok)}/{n} did NOT converge")
            if med is None:
                why.append("no rounds data")
            elif med > args.max_rounds:
                why.append(f"median rounds {med:.0f} > {args.max_rounds:.0f}")
            failures.append(f"- ❌ {regime}/{workload}: {', '.join(why)}")
        out.append(
            f"| {regime} | {workload} | {n} | {len(ok)} | {conv_rate*100:.0f}% | "
            f"{('%.0f' % med) if med is not None else '—'} | "
            f"{('%.0f' % mx) if mx is not None else '—'} | {gate} |"
        )

    out.append("")
    out.append("## Verdict\n")
    if not cells:
        out.append("- No atp-rq rows found.")
    elif failures:
        out.append("ATP-RQ convergence gate **FAILED** — these cells did not converge in bounds "
                   "(the 6.1.1 FEC-fallback fix is the lever; a high-loss large cell that fails here "
                   "is the regression to chase):")
        out.extend(failures)
    else:
        out.append("ATP-RQ converges under every measured regime within the round bound — "
                   "fail-closed and bounded, as the FEC fallback intends.")

    print("\n".join(out))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
