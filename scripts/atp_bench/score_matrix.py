#!/usr/bin/env python3
"""Score ATP-vs-rsync benchmark matrix JSONL without cross-method inflation."""

from __future__ import annotations

import argparse
import json
import math
import statistics
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


ATP_PREFIXES = ("atp", "atp-rq", "atp-quic", "rq", "quic")
RSYNC_PREFIXES = ("rsync", "rsyncd", "rsync-ssh")


@dataclass(frozen=True)
class Sample:
    workload: str
    regime: str
    tier: str
    method: str
    rep: int
    wall_s: float
    peak_rss_kb: float | None
    avg_rss_kb: float | None
    sha_ok: bool
    status: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create ATP-vs-rsync median/cv/geomean scorecards from JSONL rows."
    )
    parser.add_argument("jsonl", nargs="?", type=Path, help="matrix result JSONL")
    parser.add_argument("--out-md", type=Path, help="write markdown scorecard")
    parser.add_argument(
        "--fail-on-mismatch",
        action="store_true",
        help="exit non-zero when any row has sha_ok=false or status!=ok",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run scorer invariants without reading benchmark files",
    )
    return parser.parse_args()


def pick(row: dict[str, Any], *paths: str) -> Any:
    for path in paths:
        cur: Any = row
        ok = True
        for part in path.split("."):
            if not isinstance(cur, dict) or part not in cur:
                ok = False
                break
            cur = cur[part]
        if ok and cur is not None:
            return cur
    return None


def as_float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(number):
        return None
    return number


def as_bool(value: Any, default: bool = True) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "ok", "pass", "passed"}:
        return True
    if text in {"0", "false", "no", "fail", "failed", "mismatch"}:
        return False
    return default


def classify_method(method: str) -> str:
    lower = method.lower()
    if lower.startswith(RSYNC_PREFIXES) or "rsync" in lower:
        return "rsync"
    if lower.startswith(ATP_PREFIXES) or "atp" in lower:
        return "atp"
    return "other"


def load_samples(path: Path) -> list[Sample]:
    samples: list[Sample] = []
    with path.open("r", encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            wall = as_float(
                pick(row, "wall_s", "elapsed_s", "duration_s", "sender.wall_s", "metrics.wall_s")
            )
            if wall is None:
                continue
            method = str(pick(row, "method", "tool", "impl", "name") or "")
            if not method:
                raise ValueError(f"{path}:{line_no}: missing method")
            rep_value = pick(row, "rep", "repeat", "iteration")
            sample = Sample(
                workload=str(pick(row, "workload", "payload", "case") or "unknown"),
                regime=str(pick(row, "regime", "network", "netem.name") or "unknown"),
                tier=str(pick(row, "crypto_tier", "tier", "crypto") or "unknown"),
                method=method,
                rep=int(rep_value or 0),
                wall_s=wall,
                peak_rss_kb=as_float(
                    pick(row, "peak_rss_kb", "max_rss_kb", "time_v.max_rss_kb", "sender.maxrss_kb")
                ),
                avg_rss_kb=as_float(pick(row, "avg_rss_kb", "rss.avg_kb", "sampler.avg_rss_kb")),
                sha_ok=as_bool(pick(row, "sha_ok", "verify_ok", "sha256_ok", "integrity.sha_ok")),
                status=str(pick(row, "status", "outcome") or "ok").lower(),
            )
            samples.append(sample)
    return samples


def median(values: Iterable[float]) -> float:
    return float(statistics.median(list(values)))


def cv_pct(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    mean = statistics.fmean(values)
    if mean == 0.0:
        return 0.0
    return float(statistics.stdev(values) / mean * 100.0)


def summarize(samples: list[Sample]) -> tuple[dict[tuple[str, str, str, str], dict[str, Any]], list[Sample]]:
    grouped: dict[tuple[str, str, str, str], list[Sample]] = defaultdict(list)
    failures: list[Sample] = []
    for sample in samples:
        key = (sample.workload, sample.regime, sample.tier, sample.method)
        grouped[key].append(sample)
        if sample.status not in {"ok", "passed", "pass"} or not sample.sha_ok:
            failures.append(sample)

    summary: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for key, group in grouped.items():
        ok_group = [s for s in group if s.status in {"ok", "passed", "pass"} and s.sha_ok]
        if not ok_group:
            summary[key] = {
                "method_class": classify_method(key[3]),
                "reps": len(group),
                "ok_reps": 0,
                "wall_median_s": None,
                "wall_cv_pct": None,
                "peak_rss_median_kb": None,
                "avg_rss_median_kb": None,
                "failed": True,
            }
            continue
        walls = [s.wall_s for s in ok_group]
        peak_values = [s.peak_rss_kb for s in ok_group if s.peak_rss_kb is not None]
        avg_values = [s.avg_rss_kb for s in ok_group if s.avg_rss_kb is not None]
        summary[key] = {
            "method_class": classify_method(key[3]),
            "reps": len(group),
            "ok_reps": len(ok_group),
            "wall_median_s": median(walls),
            "wall_cv_pct": cv_pct(walls),
            "peak_rss_median_kb": median(peak_values) if peak_values else None,
            "avg_rss_median_kb": median(avg_values) if avg_values else None,
            "failed": len(ok_group) != len(group),
        }
    return summary, failures


def matched_pairs(
    summary: dict[tuple[str, str, str, str], dict[str, Any]]
) -> list[dict[str, Any]]:
    by_cell: dict[tuple[str, str, str], list[tuple[str, dict[str, Any]]]] = defaultdict(list)
    for key, stats in summary.items():
        workload, regime, tier, method = key
        by_cell[(workload, regime, tier)].append((method, stats))

    pairs: list[dict[str, Any]] = []
    for (workload, regime, tier), methods in sorted(by_cell.items()):
        atp = [
            (method, stats)
            for method, stats in methods
            if stats["method_class"] == "atp" and stats["wall_median_s"] is not None
        ]
        rsync = [
            (method, stats)
            for method, stats in methods
            if stats["method_class"] == "rsync" and stats["wall_median_s"] is not None
        ]
        if not atp or not rsync:
            continue
        for atp_method, atp_stats in atp:
            for rsync_method, rsync_stats in rsync:
                wall_ratio = atp_stats["wall_median_s"] / rsync_stats["wall_median_s"]
                rss_ratio = None
                atp_rss = atp_stats["peak_rss_median_kb"]
                rsync_rss = rsync_stats["peak_rss_median_kb"]
                if atp_rss is not None and rsync_rss not in (None, 0):
                    rss_ratio = atp_rss / rsync_rss
                pairs.append(
                    {
                        "workload": workload,
                        "regime": regime,
                        "tier": tier,
                        "atp_method": atp_method,
                        "rsync_method": rsync_method,
                        "atp_wall_s": atp_stats["wall_median_s"],
                        "rsync_wall_s": rsync_stats["wall_median_s"],
                        "wall_ratio_atp_over_rsync": wall_ratio,
                        "speedup_rsync_over_atp": 1.0 / wall_ratio if wall_ratio else None,
                        "peak_rss_ratio_atp_over_rsync": rss_ratio,
                    }
                )
    return pairs


def geomean(values: list[float]) -> float | None:
    positives = [value for value in values if value > 0 and math.isfinite(value)]
    if not positives:
        return None
    return math.exp(statistics.fmean(math.log(value) for value in positives))


def fmt(value: Any, digits: int = 3) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def render_markdown(
    summary: dict[tuple[str, str, str, str], dict[str, Any]],
    pairs: list[dict[str, Any]],
    failures: list[Sample],
) -> str:
    lines = [
        "# ATP vs rsync matrix scorecard",
        "",
        "Integrity policy: ratios compare ATP only against optimally tuned rsync in the same workload, regime, and crypto tier. Failed SHA or incomplete rows are not admitted to headline ratios.",
        "",
        "## Per-cell method medians",
        "",
        "| workload | regime | tier | method | reps | ok | median wall s | cv pct | peak rss kb |",
        "|---|---|---|---|---:|---:|---:|---:|---:|",
    ]
    for (workload, regime, tier, method), stats in sorted(summary.items()):
        lines.append(
            "| {workload} | {regime} | {tier} | {method} | {reps} | {ok} | {wall} | {cv} | {rss} |".format(
                workload=workload,
                regime=regime,
                tier=tier,
                method=method,
                reps=stats["reps"],
                ok=stats["ok_reps"],
                wall=fmt(stats["wall_median_s"]),
                cv=fmt(stats["wall_cv_pct"], 2),
                rss=fmt(stats["peak_rss_median_kb"], 0),
            )
        )

    lines.extend(
        [
            "",
            "## ATP vs rsync ratios",
            "",
            "| workload | regime | tier | ATP method | rsync method | wall ratio ATP/rsync | speedup rsync/ATP | peak RSS ratio ATP/rsync |",
            "|---|---|---|---|---|---:|---:|---:|",
        ]
    )
    for pair in pairs:
        lines.append(
            "| {workload} | {regime} | {tier} | {atp} | {rsync} | {wall} | {speedup} | {rss} |".format(
                workload=pair["workload"],
                regime=pair["regime"],
                tier=pair["tier"],
                atp=pair["atp_method"],
                rsync=pair["rsync_method"],
                wall=fmt(pair["wall_ratio_atp_over_rsync"]),
                speedup=fmt(pair["speedup_rsync_over_atp"]),
                rss=fmt(pair["peak_rss_ratio_atp_over_rsync"]),
            )
        )

    by_regime: dict[str, list[float]] = defaultdict(list)
    for pair in pairs:
        by_regime[pair["regime"]].append(pair["wall_ratio_atp_over_rsync"])
    lines.extend(["", "## Per-regime geomean", "", "| regime | geomean wall ratio ATP/rsync |", "|---|---:|"])
    for regime, values in sorted(by_regime.items()):
        lines.append(f"| {regime} | {fmt(geomean(values))} |")

    lines.extend(["", "## Failed or excluded rows", ""])
    if failures:
        lines.extend(
            [
                "| workload | regime | tier | method | rep | status | sha ok |",
                "|---|---|---|---|---:|---|---|",
            ]
        )
        for failure in failures:
            lines.append(
                f"| {failure.workload} | {failure.regime} | {failure.tier} | {failure.method} | {failure.rep} | {failure.status} | {failure.sha_ok} |"
            )
    else:
        lines.append("No failed SHA or incomplete rows were present.")

    return "\n".join(lines) + "\n"


def run_self_test() -> int:
    rows = [
        Sample("50M", "bad", "auth", "atp-rq-auth", 1, 10.0, 100.0, None, True, "ok"),
        Sample("50M", "bad", "auth", "atp-rq-auth", 2, 12.0, 120.0, None, True, "ok"),
        Sample("50M", "bad", "auth", "rsync-ssh-aes128gcm", 1, 20.0, 200.0, None, True, "ok"),
        Sample("50M", "bad", "auth", "rsync-ssh-aes128gcm", 2, 22.0, 220.0, None, True, "ok"),
        Sample("50M", "bad", "auth", "atp-rq-auth", 3, 11.0, 110.0, None, False, "mismatch"),
    ]
    summary, failures = summarize(rows)
    pairs = matched_pairs(summary)
    assert failures and failures[0].sha_ok is False
    assert pairs and round(pairs[0]["wall_ratio_atp_over_rsync"], 3) == 0.524
    assert "ATP vs rsync" in render_markdown(summary, pairs, failures)
    return 0


def main() -> int:
    args = parse_args()
    if args.self_test:
        return run_self_test()
    if args.jsonl is None:
        raise ValueError("missing matrix result JSONL")
    samples = load_samples(args.jsonl)
    summary, failures = summarize(samples)
    pairs = matched_pairs(summary)
    markdown = render_markdown(summary, pairs, failures)
    if args.out_md:
        args.out_md.parent.mkdir(parents=True, exist_ok=True)
        args.out_md.write_text(markdown, encoding="utf-8")
    else:
        sys.stdout.write(markdown)
    if args.fail_on_mismatch and failures:
        return 3
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BrokenPipeError:
        raise SystemExit(1)
    except Exception as exc:
        print(f"score_matrix.py: {exc}", file=sys.stderr)
        raise SystemExit(2)
