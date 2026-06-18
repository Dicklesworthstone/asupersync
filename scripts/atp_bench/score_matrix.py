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
    stream_count: int | None
    rep: int
    wall_s: float
    peak_rss_kb: float | None
    avg_rss_kb: float | None
    sender_peak_rss_kb: float | None
    receiver_peak_rss_kb: float | None
    sender_avg_rss_kb: float | None
    receiver_avg_rss_kb: float | None
    feedback_rounds: float | None
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


def as_int(value: Any) -> int | None:
    number = as_float(value)
    if number is None:
        return None
    whole = int(number)
    if whole != number:
        return None
    return whole


def classify_method(method: str) -> str:
    lower = method.lower()
    if lower.startswith(RSYNC_PREFIXES) or "rsync" in lower:
        return "rsync"
    if lower.startswith(ATP_PREFIXES) or "atp" in lower:
        return "atp"
    return "other"


def crypto_symmetric_pair(tier: str, atp_method: str, rsync_method: str) -> tuple[bool, str]:
    tier_l = tier.lower()
    atp_l = atp_method.lower()
    rsync_l = rsync_method.lower()
    if tier_l == "nocrypto":
        if ("lab" in atp_l or "nocrypto" in atp_l) and ("rsyncd" in rsync_l or "daemon" in rsync_l):
            return True, ""
        return False, "nocrypto tier requires atp lab/nocrypto vs rsyncd"
    if tier_l == "auth":
        if ("auth" in atp_l or "key" in atp_l) and ("ssh" in rsync_l or "aes128gcm" in rsync_l):
            return True, ""
        return False, "auth tier requires authenticated ATP vs rsync-over-ssh"
    if tier_l == "encrypted":
        atp_encrypted = "quic" in atp_l or "tls" in atp_l or "encrypted" in atp_l
        rsync_encrypted = "ssh" in rsync_l or "aes128gcm" in rsync_l
        if atp_encrypted and rsync_encrypted:
            return True, ""
        return False, "encrypted tier requires atp-quic/TLS vs rsync-over-ssh"
    return False, f"unknown crypto tier {tier!r}; ratio excluded"


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
            stream_count = as_int(
                pick(
                    row,
                    "atp_rq_streams",
                    "stream_count",
                    "streams",
                    "rq.streams",
                    "conditions.atp_rq_streams",
                )
            )
            sample = Sample(
                workload=str(pick(row, "workload", "payload", "case") or "unknown"),
                regime=str(pick(row, "regime", "network", "netem.name") or "unknown"),
                tier=str(pick(row, "crypto_tier", "tier", "crypto") or "unknown"),
                method=method,
                stream_count=stream_count,
                rep=int(rep_value or 0),
                wall_s=wall,
                peak_rss_kb=as_float(
                    pick(row, "peak_rss_kb", "max_rss_kb", "time_v.max_rss_kb", "sender.maxrss_kb")
                ),
                avg_rss_kb=as_float(pick(row, "avg_rss_kb", "rss.avg_kb", "sampler.avg_rss_kb")),
                sender_peak_rss_kb=as_float(
                    pick(
                        row,
                        "sender_peak_rss_kb",
                        "sender.max_rss_kb",
                        "sender.maxrss_kb",
                        "sender_time.max_rss_kb",
                    )
                ),
                receiver_peak_rss_kb=as_float(
                    pick(
                        row,
                        "receiver_peak_rss_kb",
                        "receiver.max_rss_kb",
                        "receiver.maxrss_kb",
                        "receiver_time.max_rss_kb",
                        "receiver_sampler.peak_rss_kb",
                    )
                ),
                sender_avg_rss_kb=as_float(
                    pick(row, "sender_avg_rss_kb", "sender.avg_rss_kb", "sender_sampler.avg_rss_kb")
                ),
                receiver_avg_rss_kb=as_float(
                    pick(row, "receiver_avg_rss_kb", "receiver.avg_rss_kb", "receiver_sampler.avg_rss_kb")
                ),
                feedback_rounds=as_float(
                    pick(row, "feedback_rounds", "rq.feedback_rounds", "metrics.feedback_rounds")
                ),
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


SummaryKey = tuple[str, str, str, str, str]


def stream_key(sample: Sample) -> str:
    if classify_method(sample.method) == "atp" and sample.stream_count is not None:
        return str(sample.stream_count)
    return ""


def summarize(samples: list[Sample]) -> tuple[dict[SummaryKey, dict[str, Any]], list[Sample]]:
    grouped: dict[SummaryKey, list[Sample]] = defaultdict(list)
    failures: list[Sample] = []
    for sample in samples:
        key = (sample.workload, sample.regime, sample.tier, sample.method, stream_key(sample))
        grouped[key].append(sample)
        if sample.status not in {"ok", "passed", "pass"} or not sample.sha_ok:
            failures.append(sample)

    summary: dict[SummaryKey, dict[str, Any]] = {}
    for key, group in grouped.items():
        ok_group = [s for s in group if s.status in {"ok", "passed", "pass"} and s.sha_ok]
        if not ok_group:
            summary[key] = {
                "method_class": classify_method(key[3]),
                "stream_count": key[4] or None,
                "reps": len(group),
                "ok_reps": 0,
                "wall_median_s": None,
                "wall_cv_pct": None,
                "peak_rss_median_kb": None,
                "avg_rss_median_kb": None,
                "sender_peak_rss_median_kb": None,
                "receiver_peak_rss_median_kb": None,
                "sender_avg_rss_median_kb": None,
                "receiver_avg_rss_median_kb": None,
                "feedback_rounds_median": None,
                "failed": True,
            }
            continue
        walls = [s.wall_s for s in ok_group]
        peak_values = [s.peak_rss_kb for s in ok_group if s.peak_rss_kb is not None]
        avg_values = [s.avg_rss_kb for s in ok_group if s.avg_rss_kb is not None]
        sender_peak_values = [s.sender_peak_rss_kb for s in ok_group if s.sender_peak_rss_kb is not None]
        receiver_peak_values = [
            s.receiver_peak_rss_kb for s in ok_group if s.receiver_peak_rss_kb is not None
        ]
        sender_avg_values = [s.sender_avg_rss_kb for s in ok_group if s.sender_avg_rss_kb is not None]
        receiver_avg_values = [
            s.receiver_avg_rss_kb for s in ok_group if s.receiver_avg_rss_kb is not None
        ]
        feedback_values = [s.feedback_rounds for s in ok_group if s.feedback_rounds is not None]
        summary[key] = {
            "method_class": classify_method(key[3]),
            "stream_count": key[4] or None,
            "reps": len(group),
            "ok_reps": len(ok_group),
            "wall_median_s": median(walls),
            "wall_cv_pct": cv_pct(walls),
            "peak_rss_median_kb": median(peak_values) if peak_values else None,
            "avg_rss_median_kb": median(avg_values) if avg_values else None,
            "sender_peak_rss_median_kb": median(sender_peak_values) if sender_peak_values else None,
            "receiver_peak_rss_median_kb": median(receiver_peak_values) if receiver_peak_values else None,
            "sender_avg_rss_median_kb": median(sender_avg_values) if sender_avg_values else None,
            "receiver_avg_rss_median_kb": median(receiver_avg_values) if receiver_avg_values else None,
            "feedback_rounds_median": median(feedback_values) if feedback_values else None,
            "failed": len(ok_group) != len(group),
        }
    return summary, failures


def matched_pairs(
    summary: dict[SummaryKey, dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    by_cell: dict[tuple[str, str, str], list[tuple[str, dict[str, Any]]]] = defaultdict(list)
    for key, stats in summary.items():
        workload, regime, tier, method, _stream = key
        by_cell[(workload, regime, tier)].append((method, stats))

    pairs: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
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
                symmetric, reason = crypto_symmetric_pair(tier, atp_method, rsync_method)
                if not symmetric:
                    excluded.append(
                        {
                            "workload": workload,
                            "regime": regime,
                            "tier": tier,
                            "atp_method": atp_method,
                            "atp_streams": atp_stats["stream_count"],
                            "rsync_method": rsync_method,
                            "reason": reason,
                        }
                    )
                    continue
                wall_ratio = atp_stats["wall_median_s"] / rsync_stats["wall_median_s"]
                rss_ratio = None
                atp_rss = atp_stats["peak_rss_median_kb"]
                rsync_rss = rsync_stats["peak_rss_median_kb"]
                if atp_rss is not None and rsync_rss not in (None, 0):
                    rss_ratio = atp_rss / rsync_rss
                sender_rss_ratio = None
                receiver_rss_ratio = None
                if (
                    atp_stats["sender_peak_rss_median_kb"] is not None
                    and rsync_stats["sender_peak_rss_median_kb"] not in (None, 0)
                ):
                    sender_rss_ratio = (
                        atp_stats["sender_peak_rss_median_kb"]
                        / rsync_stats["sender_peak_rss_median_kb"]
                    )
                if (
                    atp_stats["receiver_peak_rss_median_kb"] is not None
                    and rsync_stats["receiver_peak_rss_median_kb"] not in (None, 0)
                ):
                    receiver_rss_ratio = (
                        atp_stats["receiver_peak_rss_median_kb"]
                        / rsync_stats["receiver_peak_rss_median_kb"]
                    )
                pairs.append(
                    {
                        "workload": workload,
                        "regime": regime,
                        "tier": tier,
                        "atp_method": atp_method,
                        "atp_streams": atp_stats["stream_count"],
                        "rsync_method": rsync_method,
                        "atp_wall_s": atp_stats["wall_median_s"],
                        "rsync_wall_s": rsync_stats["wall_median_s"],
                        "wall_ratio_atp_over_rsync": wall_ratio,
                        "speedup_rsync_over_atp": 1.0 / wall_ratio if wall_ratio else None,
                        "peak_rss_ratio_atp_over_rsync": rss_ratio,
                        "sender_peak_rss_ratio_atp_over_rsync": sender_rss_ratio,
                        "receiver_peak_rss_ratio_atp_over_rsync": receiver_rss_ratio,
                        "atp_feedback_rounds": atp_stats["feedback_rounds_median"],
                    }
                )
    return pairs, excluded


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
    summary: dict[SummaryKey, dict[str, Any]],
    pairs: list[dict[str, Any]],
    excluded_pairs: list[dict[str, Any]],
    failures: list[Sample],
) -> str:
    lines = [
        "# ATP vs rsync matrix scorecard",
        "",
        "Integrity policy: ratios compare ATP only against optimally tuned rsync in the same workload, regime, and crypto tier. Failed SHA or incomplete rows are not admitted to headline ratios.",
        "",
        "## Per-cell method medians",
        "",
        "| workload | regime | tier | method | ATP streams | reps | ok | status | median wall s | cv pct | sender peak RSS KB | receiver peak RSS KB | combined peak RSS KB | feedback rounds |",
        "|---|---|---|---|---:|---:|---:|---|---:|---:|---:|---:|---:|---:|",
    ]
    for (workload, regime, tier, method, _stream), stats in sorted(summary.items()):
        status = "OK"
        if stats["ok_reps"] == 0:
            status = "FAIL"
        elif stats["failed"]:
            status = "PARTIAL"
        lines.append(
            "| {workload} | {regime} | {tier} | {method} | {streams} | {reps} | {ok} | {status} | {wall} | {cv} | {sender_rss} | {receiver_rss} | {rss} | {rounds} |".format(
                workload=workload,
                regime=regime,
                tier=tier,
                method=method,
                streams=fmt(stats["stream_count"], 0),
                reps=stats["reps"],
                ok=stats["ok_reps"],
                status=status,
                wall=fmt(stats["wall_median_s"]),
                cv=fmt(stats["wall_cv_pct"], 2),
                sender_rss=fmt(stats["sender_peak_rss_median_kb"], 0),
                receiver_rss=fmt(stats["receiver_peak_rss_median_kb"], 0),
                rss=fmt(stats["peak_rss_median_kb"], 0),
                rounds=fmt(stats["feedback_rounds_median"], 0),
            )
        )

    lines.extend(
        [
            "",
            "## ATP vs rsync ratios",
            "",
            "Only crypto-symmetric, same-cell ATP-vs-rsync pairs are admitted here.",
            "",
            "| workload | regime | tier | ATP method | ATP streams | rsync method | wall ratio ATP/rsync | speedup rsync/ATP | sender RSS ratio | receiver RSS ratio | combined peak RSS ratio | ATP feedback rounds |",
            "|---|---|---|---|---:|---|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for pair in pairs:
        lines.append(
            "| {workload} | {regime} | {tier} | {atp} | {streams} | {rsync} | {wall} | {speedup} | {sender_rss} | {receiver_rss} | {rss} | {rounds} |".format(
                workload=pair["workload"],
                regime=pair["regime"],
                tier=pair["tier"],
                atp=pair["atp_method"],
                streams=fmt(pair["atp_streams"], 0),
                rsync=pair["rsync_method"],
                wall=fmt(pair["wall_ratio_atp_over_rsync"]),
                speedup=fmt(pair["speedup_rsync_over_atp"]),
                sender_rss=fmt(pair["sender_peak_rss_ratio_atp_over_rsync"]),
                receiver_rss=fmt(pair["receiver_peak_rss_ratio_atp_over_rsync"]),
                rss=fmt(pair["peak_rss_ratio_atp_over_rsync"]),
                rounds=fmt(pair["atp_feedback_rounds"], 0),
            )
        )

    by_regime: dict[str, list[float]] = defaultdict(list)
    for pair in pairs:
        by_regime[pair["regime"]].append(pair["wall_ratio_atp_over_rsync"])
    lines.extend(["", "## Per-regime geomean", "", "| regime | geomean wall ratio ATP/rsync |", "|---|---:|"])
    for regime, values in sorted(by_regime.items()):
        lines.append(f"| {regime} | {fmt(geomean(values))} |")

    lines.extend(["", "## Excluded asymmetric ratios", ""])
    if excluded_pairs:
        lines.extend(
            [
                "| workload | regime | tier | ATP method | ATP streams | rsync method | reason |",
                "|---|---|---|---|---:|---|---|",
            ]
        )
        for pair in excluded_pairs:
            lines.append(
                f"| {pair['workload']} | {pair['regime']} | {pair['tier']} | {pair['atp_method']} | {fmt(pair.get('atp_streams'), 0)} | {pair['rsync_method']} | {pair['reason']} |"
            )
    else:
        lines.append("No asymmetric ATP/rsync pairs were present.")

    lines.extend(["", "## Failed or excluded rows", ""])
    if failures:
        lines.extend(
            [
                "| workload | regime | tier | method | ATP streams | rep | status | sha ok |",
                "|---|---|---|---|---:|---:|---|---|",
            ]
        )
        for failure in failures:
            lines.append(
                f"| {failure.workload} | {failure.regime} | {failure.tier} | {failure.method} | {fmt(failure.stream_count, 0)} | {failure.rep} | {failure.status} | {failure.sha_ok} |"
            )
    else:
        lines.append("No failed SHA or incomplete rows were present.")

    return "\n".join(lines) + "\n"


def run_self_test() -> int:
    rows = [
        Sample("50M", "bad", "auth", "atp-rq-auth", 4, 1, 10.0, 100.0, None, 40.0, 100.0, None, None, 1.0, True, "ok"),
        Sample("50M", "bad", "auth", "atp-rq-auth", 4, 2, 12.0, 120.0, None, 60.0, 120.0, None, None, 1.0, True, "ok"),
        Sample("50M", "bad", "auth", "rsync-ssh-aes128gcm", None, 1, 20.0, 200.0, None, 90.0, 200.0, None, None, None, True, "ok"),
        Sample("50M", "bad", "auth", "rsync-ssh-aes128gcm", None, 2, 22.0, 220.0, None, 110.0, 220.0, None, None, None, True, "ok"),
        Sample("50M", "bad", "auth", "atp-rq-auth", 4, 3, 11.0, 110.0, None, 55.0, 110.0, None, None, 2.0, False, "mismatch"),
        Sample("50M", "bad", "auth", "atp-rq-lab", 1, 1, 9.0, 90.0, None, 35.0, 90.0, None, None, 0.0, True, "ok"),
    ]
    summary, failures = summarize(rows)
    pairs, excluded_pairs = matched_pairs(summary)
    assert failures and failures[0].sha_ok is False
    assert pairs and round(pairs[0]["wall_ratio_atp_over_rsync"], 3) == 0.524
    assert pairs[0]["atp_streams"] == "4"
    assert excluded_pairs and excluded_pairs[0]["atp_method"] == "atp-rq-lab"
    assert round(pairs[0]["receiver_peak_rss_ratio_atp_over_rsync"], 3) == 0.524
    assert "ATP vs rsync" in render_markdown(summary, pairs, excluded_pairs, failures)
    return 0


def main() -> int:
    args = parse_args()
    if args.self_test:
        return run_self_test()
    if args.jsonl is None:
        raise ValueError("missing matrix result JSONL")
    samples = load_samples(args.jsonl)
    summary, failures = summarize(samples)
    pairs, excluded_pairs = matched_pairs(summary)
    markdown = render_markdown(summary, pairs, excluded_pairs, failures)
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
