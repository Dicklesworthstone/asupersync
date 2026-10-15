#!/usr/bin/env python3
"""apply_perf_ratchet.py — pass-over-pass performance ratchet (gauntlet PERF-004).

Consumes the append-only `.bench-history/` substrate produced by
`scripts/capture_baseline.sh --bench-history` (one `<bench>.latest.json` per
benchmark = the committed keep-gate baseline) and compares a freshly-captured
CANDIDATE baseline (the `asupersync.baseline.v2` JSON that capture_baseline.sh
prints / saves) against it.

Verdicts (mirrors FrankenSQLite `comprehensive-bench-ci-regression-gate.v2`):

  * Quarantine — the cv_pct for a benchmark exceeds the flake threshold on
    EITHER side (candidate or committed baseline), so its comparison is noise
    and is NOT scored (neither pass nor fail). The quarantine record's `side`
    field says which side was flaky. Checking the baseline side matters: a
    contention-noisy committed baseline would otherwise produce phantom
    Block/Allow verdicts on every future comparison (gauntlet PERF-R3,
    br-asupersync-4j4h32).
  * Block      — a scored benchmark regressed past its per-bench threshold, OR
    the geomean ratio regressed past the geomean threshold.
  * Allow      — every scored benchmark and the geomean are within thresholds.

Latency metrics: lower ns is better, so a regression is
`candidate / baseline - 1 > threshold`.

Optional `--eprocess` runs an anytime-valid betting martingale (Ville's
inequality) over the per-bench regression-indicator stream in
`.bench-history/runs.jsonl`, raising an alarm if the e-value crosses `1/alpha`.
This reuses the calibration spirit of `src/lab/oracle/eprocess.rs`.

Exit codes: 0 = Allow, 2 = Block, 3 = Quarantine-only (no block, but flaky
benches were excluded from scoring). The e-process alarm is advisory and is
reported in the JSON; with `--eprocess-fail` it upgrades Allow -> Block.

Usage:
  apply_perf_ratchet.py --candidate <baseline.json> [--history-dir .bench-history]
        [--metric median_ns] [--per-bench-max-regression-pct 10]
        [--geomean-max-regression-pct 5] [--cv-pct-flake-threshold 5]
        [--eprocess] [--eprocess-alpha 0.001] [--eprocess-p0 1e-6]
        [--eprocess-lambda 0.9] [--eprocess-fail] [--json]
"""
from __future__ import annotations

import argparse
import json
import math
import os
import sys
from typing import Optional


def load_candidate(path: str) -> dict:
    with open(path, "r") as fh:
        data = json.load(fh)
    return {b["name"]: b for b in data.get("benchmarks", []) if "name" in b}


def load_history_baseline(history_dir: str) -> dict:
    """Read every `<bench>.latest.json` as the committed keep-gate baseline."""
    baseline: dict[str, dict] = {}
    if not os.path.isdir(history_dir):
        return baseline
    for fname in os.listdir(history_dir):
        if not fname.endswith(".latest.json"):
            continue
        with open(os.path.join(history_dir, fname), "r") as fh:
            rec = json.load(fh)
        name = rec.get("name")
        if name:
            baseline[name] = rec
    return baseline


def load_combined_baseline(path: str) -> dict:
    """Read a combined `asupersync.baseline.v2` file (capture_baseline.sh --save
    output) as the baseline. Used in CI's base-vs-PR flow where there is no
    committed `.bench-history` yet."""
    with open(path, "r") as fh:
        data = json.load(fh)
    return {b["name"]: b for b in data.get("benchmarks", []) if "name" in b}


def is_number(x) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x)


def eprocess_alarm(runs_path: str, metric: str, per_bench_thr_pct: float,
                   alpha: float, p0: float, lam: float,
                   cv_pct_flake_threshold: float = 5.0) -> Optional[dict]:
    """Anytime-valid betting martingale over the per-bench regression stream.

    For each benchmark, order its history records by `generated_at`; each
    consecutive pair yields a regression indicator X in {0,1}
    (X=1 iff cur/prev - 1 > per_bench_thr). The e-value updates multiplicatively
    E *= 1 + lam * (X - p0), clamped at >= 0. Alarm iff E >= 1/alpha.

    Flake filtering (gauntlet PERF-R5, br-asupersync FUZZ-R5 sibling finding):
    pairs where EITHER record has cv_pct above the flake threshold are skipped
    and counted in `skipped_flaky_pairs`. Without this, noisy capture history
    (shared-VPS contention swings of +/-20%) reads as a stream of phantom
    regressions and the e-value alarms on pure noise.
    """
    if not os.path.isfile(runs_path):
        return None
    by_bench: dict[str, list] = {}
    with open(runs_path, "r") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            by_bench.setdefault(rec.get("name", ""), []).append(rec)

    def is_flaky(rec: dict) -> bool:
        cv = rec.get("cv_pct")
        return is_number(cv) and cv > cv_pct_flake_threshold

    thr = per_bench_thr_pct / 100.0
    e_value = 1.0
    observations = 0
    regressions = 0
    skipped_flaky_pairs = 0
    for name, recs in by_bench.items():
        recs.sort(key=lambda r: r.get("generated_at", ""))
        for prev, cur in zip(recs, recs[1:]):
            if is_flaky(prev) or is_flaky(cur):
                skipped_flaky_pairs += 1
                continue
            pv, cv = prev.get(metric), cur.get(metric)
            if not (is_number(pv) and is_number(cv) and pv > 0):
                continue
            x = 1.0 if (cv / pv - 1.0) > thr else 0.0
            e_value = max(0.0, e_value * (1.0 + lam * (x - p0)))
            observations += 1
            regressions += int(x)
    threshold = 1.0 / alpha if alpha > 0 else math.inf
    return {
        "e_value": e_value,
        "threshold": threshold,
        "alarm": e_value >= threshold,
        "observations": observations,
        "regressions": regressions,
        "skipped_flaky_pairs": skipped_flaky_pairs,
        "params": {"alpha": alpha, "p0": p0, "lambda": lam,
                   "cv_pct_flake_threshold": cv_pct_flake_threshold},
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Pass-over-pass perf ratchet (PERF-004)")
    ap.add_argument("--candidate", required=True, help="candidate baseline JSON (capture_baseline.sh output)")
    ap.add_argument("--history-dir", default=".bench-history",
                    help="committed keep-gate baseline dir (default mode)")
    ap.add_argument("--baseline", default=None,
                    help="combined baseline JSON to use instead of --history-dir "
                         "(CI base-vs-PR flow; capture_baseline.sh --save output)")
    ap.add_argument("--metric", default="median_ns",
                    choices=["mean_ns", "median_ns", "p95_ns", "p99_ns"])
    ap.add_argument("--per-bench-max-regression-pct", type=float, default=10.0)
    ap.add_argument("--geomean-max-regression-pct", type=float, default=5.0)
    ap.add_argument("--cv-pct-flake-threshold", type=float, default=5.0)
    ap.add_argument("--eprocess", action="store_true")
    ap.add_argument("--eprocess-alpha", type=float, default=0.001)
    ap.add_argument("--eprocess-p0", type=float, default=1e-6)
    ap.add_argument("--eprocess-lambda", type=float, default=0.9)
    ap.add_argument("--eprocess-fail", action="store_true",
                    help="treat an e-process alarm as a Block")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    candidate = load_candidate(args.candidate)
    if args.baseline:
        baseline = load_combined_baseline(args.baseline)
        baseline_source = args.baseline
    else:
        baseline = load_history_baseline(args.history_dir)
        baseline_source = args.history_dir

    metric = args.metric

    scored: list[dict] = []
    blocked: list[dict] = []
    quarantined: list[dict] = []
    missing_baseline: list[str] = []
    ratios: list[float] = []

    for name, cur in sorted(candidate.items()):
        cv_pct = cur.get("cv_pct")
        if is_number(cv_pct) and cv_pct > args.cv_pct_flake_threshold:
            quarantined.append({"name": name, "cv_pct": cv_pct, "side": "candidate"})
            continue
        base = baseline.get(name)
        if base is None:
            missing_baseline.append(name)
            continue
        # Two-sided flake check (br-asupersync-4j4h32): a flaky committed
        # baseline must not be scored either, or every future comparison
        # against it yields phantom regressions/improvements.
        base_cv = base.get("cv_pct")
        if is_number(base_cv) and base_cv > args.cv_pct_flake_threshold:
            quarantined.append({"name": name, "cv_pct": base_cv, "side": "baseline"})
            continue
        cur_val, base_val = cur.get(metric), base.get(metric)
        if not (is_number(cur_val) and is_number(base_val) and base_val > 0):
            continue
        ratio = cur_val / base_val
        delta_pct = (ratio - 1.0) * 100.0
        ratios.append(ratio)
        row = {"name": name, "baseline": base_val, "candidate": cur_val,
               "ratio": ratio, "delta_pct": delta_pct}
        scored.append(row)
        if delta_pct > args.per_bench_max_regression_pct:
            blocked.append(row)

    geomean_ratio = (math.exp(sum(math.log(r) for r in ratios) / len(ratios))
                     if ratios else 1.0)
    geomean_delta_pct = (geomean_ratio - 1.0) * 100.0
    geomean_blocked = geomean_delta_pct > args.geomean_max_regression_pct

    eproc = None
    if args.eprocess:
        eproc = eprocess_alarm(
            os.path.join(args.history_dir, "runs.jsonl"), metric, args.per_bench_max_regression_pct,
            args.eprocess_alpha, args.eprocess_p0, args.eprocess_lambda,
            cv_pct_flake_threshold=args.cv_pct_flake_threshold)

    if blocked or geomean_blocked or (args.eprocess_fail and eproc and eproc.get("alarm")):
        verdict = "Block"
    elif quarantined and not scored:
        verdict = "Quarantine"
    else:
        verdict = "Allow"

    report = {
        "schema_version": "asupersync.perf_ratchet.v1",
        "verdict": verdict,
        "baseline_source": baseline_source,
        "metric": metric,
        "thresholds": {
            "per_bench_max_regression_pct": args.per_bench_max_regression_pct,
            "geomean_max_regression_pct": args.geomean_max_regression_pct,
            "cv_pct_flake_threshold": args.cv_pct_flake_threshold,
        },
        "scored_count": len(scored),
        "geomean_ratio": geomean_ratio,
        "geomean_delta_pct": geomean_delta_pct,
        "geomean_blocked": geomean_blocked,
        "blocked": blocked,
        "quarantined": quarantined,
        "missing_baseline": missing_baseline,
        "eprocess": eproc,
    }

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"verdict: {verdict}  (metric={metric}, scored={len(scored)}, "
              f"geomean_delta={geomean_delta_pct:+.2f}%)")
        for r in blocked:
            print(f"  BLOCK {r['name']}: {r['baseline']:.2f} -> {r['candidate']:.2f} ({r['delta_pct']:+.2f}%)")
        if geomean_blocked:
            print(f"  BLOCK geomean: {geomean_delta_pct:+.2f}% > {args.geomean_max_regression_pct}%")
        for q in quarantined:
            side = q.get("side", "candidate")
            print(f"  QUARANTINE {q['name']} ({side}): cv_pct={q['cv_pct']:.2f} > {args.cv_pct_flake_threshold}")
        if missing_baseline:
            print(f"  note: {len(missing_baseline)} benchmark(s) had no .bench-history baseline (new benches)")
        if eproc:
            print(f"  e-process: E={eproc['e_value']:.3g} vs 1/alpha={eproc['threshold']:.3g} "
                  f"alarm={eproc['alarm']} (obs={eproc['observations']}, regressions={eproc['regressions']}, "
                  f"skipped_flaky_pairs={eproc.get('skipped_flaky_pairs', 0)})")

    return {"Allow": 0, "Block": 2, "Quarantine": 3}[verdict]


if __name__ == "__main__":
    sys.exit(main())
