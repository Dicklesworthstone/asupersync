#!/usr/bin/env python3
"""Aggregate atp_bench results.jsonl into a markdown report (br-asupersync-iiz6jk).

Usage: report.py results.jsonl [conditions.json] > report.md

Warmup runs (run == 0) are listed but excluded from aggregates. Failed
verifications are never dropped; they fail the row loudly.
"""

import json
import statistics
import sys
from collections import defaultdict


def fmt_bytes(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def cv_pct(values):
    if len(values) < 2:
        return 0.0
    mean = statistics.mean(values)
    if mean <= 0:
        return 0.0
    return statistics.stdev(values) / mean * 100.0


def crypto_symmetric_pairs(tools):
    pairs = []
    tool_set = set(tools)
    if "rsync-ssh" in tool_set:
        for atp in ("atp-quic", "atp-rq"):
            if atp in tool_set:
                pairs.append((atp, "rsync-ssh"))
    if "rsyncd" in tool_set:
        for atp in ("atp-tcp",):
            if atp in tool_set:
                pairs.append((atp, "rsyncd"))
    return pairs


def load_jsonl(path):
    rows = []
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise SystemExit(f"{path}:{lineno}: invalid JSON: {exc}") from exc
    return rows


def load_json(path):
    with open(path, encoding="utf-8") as fh:
        try:
            return json.load(fh)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"{path}: invalid JSON: {exc}") from exc


def resource_guard_ok(row):
    ok = row["resource_guard"].get("ok")
    return isinstance(ok, bool) and ok


def main():
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    rows = load_jsonl(sys.argv[1])
    conditions = {}
    if len(sys.argv) > 2:
        conditions = load_json(sys.argv[2])

    print("# ATP vs rsync — real-internet benchmark report\n")
    if conditions:
        print(f"- **Date**: {conditions.get('date')}")
        print(f"- **Sender → Receiver**: `{conditions.get('sender')}` → `{conditions.get('receiver')}` (open internet)")
        print(f"- **RTT**: {conditions.get('rtt')}")
        print(f"- **Cores**: sender {conditions.get('sender_cores')}, receiver {conditions.get('receiver_cores')}")
        print(f"- **Runs per cell**: {conditions.get('runs')} measured + 1 warmup (warmup excluded from aggregates)\n")
        if "atp_rq_streams" in conditions:
            print(
                f"- **ATP RQ settings**: streams {conditions.get('atp_rq_streams')}, "
                f"symbol size {conditions.get('atp_rq_symbol_size')} bytes, "
                f"repair overhead {conditions.get('atp_rq_repair_overhead')}\n"
            )
    print("Note: `atp-quic` is the QUIC/TLS ATP row; `atp-rq` is the\n"
          "authenticated RaptorQ/UDP ATP row; `atp-tcp` is the plaintext legacy\n"
          "ATP control row. `rsyncd` is the plaintext rsync ceiling, and\n"
          "`rsync-ssh` is the authenticated/encrypted rsync row.\n")

    # Group measured runs.
    groups = defaultdict(list)
    fails = []
    for r in rows:
        if not r.get("verify_ok"):
            fails.append(r)
        if r["run"] == 0:
            continue
        groups[(r["payload"], r["tool"])].append(r)

    payloads = []
    tools = []
    for (p, t) in groups:
        if p not in payloads:
            payloads.append(p)
        if t not in tools:
            tools.append(t)

    print("## Wall clock / throughput (mean of measured runs)\n")
    print("| Payload | Size | " + " | ".join(f"{t} wall (s) | {t} cv_pct | {t} MB/s" for t in tools) + " |")
    print("|---" * (2 + 3 * len(tools)) + "|")
    for p in payloads:
        size = None
        cells = []
        for t in tools:
            runs = groups.get((p, t), [])
            walls = [r["sender"]["wall_s"] for r in runs
                     if r["sender"]["wall_s"] is not None and r.get("verify_ok")]
            if runs and size is None:
                size = runs[0]["sender"]["bytes"]
            if walls:
                mean_wall = statistics.mean(walls)
                mbps = (size / 1048576) / mean_wall if mean_wall > 0 else 0
                spread = f" ±{statistics.stdev(walls):.2f}" if len(walls) > 1 else ""
                cells.append(f"{mean_wall:.2f}{spread} | {cv_pct(walls):.1f} | {mbps:.1f}")
            else:
                cells.append("FAIL | — | —")
        print(f"| {p} | {fmt_bytes(size or 0)} | " + " | ".join(cells) + " |")

    print("\n## Resources (mean of measured runs)\n")
    print("| Payload | Tool | Sender peak RSS | Recv peak RSS | Sender CPU s (u+s) | "
          "Cycles (G) | Instr (G) | Avg core util % | Peak load1 (recv) | Feedback rounds |")
    print("|---|---|---|---|---|---|---|---|---|---|")
    for p in payloads:
        for t in tools:
            runs = [r for r in groups.get((p, t), []) if r.get("verify_ok")]
            if not runs:
                print(f"| {p} | {t} | FAILED VERIFY OR NO RUNS | | | | | | | |")
                continue

            def mean_of(path, scale=1.0):
                vals = []
                for r in runs:
                    v = r
                    for k in path:
                        v = v.get(k) if isinstance(v, dict) else None
                        if v is None:
                            break
                    if isinstance(v, (int, float)):
                        vals.append(v / scale)
                return statistics.mean(vals) if vals else None

            s_rss = mean_of(["sender", "max_rss_kb"], 1024)
            r_rss_t = mean_of(["receiver_time", "max_rss_kb"], 1024)
            r_rss_s = mean_of(["receiver_sampler", "peak_rss_kb"], 1024)
            r_rss = r_rss_t if r_rss_t else r_rss_s
            cpu_u = mean_of(["sender", "user_s"]) or 0
            cpu_s = mean_of(["sender", "sys_s"]) or 0
            cyc = mean_of(["sender", "cycles"], 1e9)
            ins = mean_of(["sender", "instructions"], 1e9)
            util = mean_of(["sender", "avg_core_util_pct"])
            load = mean_of(["receiver_sampler", "peak_load1"])
            rounds = mean_of(["sender", "feedback_rounds"])

            def cell(value, fmt):
                return fmt.format(value) if value is not None else "—"

            print(f"| {p} | {t} "
                  f"| {cell(s_rss, '{:.0f} MB')} "
                  f"| {cell(r_rss, '{:.0f} MB')} "
                  f"| {cpu_u + cpu_s:.2f} "
                  f"| {cell(cyc, '{:.2f}')} "
                  f"| {cell(ins, '{:.2f}')} "
                  f"| {cell(util, '{:.0f}')} "
                  f"| {cell(load, '{:.2f}')} "
                  f"| {cell(rounds, '{:.1f}')} |")

    print("\n## Resource Guard\n")
    load_cap = conditions.get("max_load_per_core")
    sender_rss_cap = conditions.get("max_sender_rss_mb")
    receiver_rss_cap = conditions.get("max_receiver_rss_mb")
    if load_cap is not None or sender_rss_cap is not None or receiver_rss_cap is not None:
        print(
            f"- Configured caps: load1 <= {load_cap}x cores; "
            f"sender RSS <= {sender_rss_cap} MiB; receiver RSS <= {receiver_rss_cap} MiB."
        )
    guard_rows = [
        r for r in rows
        if r.get("run") != 0 and isinstance(r.get("resource_guard"), dict)
    ]
    if not guard_rows:
        print("- No `resource_guard` objects were present in measured rows.")
    else:
        print("| Payload | Tool | Guard pass | Worst observed / limit | Status |")
        print("|---|---|---|---|---|")
        for p in payloads:
            for t in tools:
                runs = [
                    r for r in groups.get((p, t), [])
                    if isinstance(r.get("resource_guard"), dict)
                ]
                if not runs:
                    print(f"| {p} | {t} | 0/0 | - | MISSING |")
                    continue
                passed = sum(1 for r in runs if resource_guard_ok(r))
                worst = None
                for r in runs:
                    for check in r["resource_guard"].get("checks", []):
                        limit = check.get("limit")
                        observed = check.get("observed")
                        if not isinstance(limit, (int, float)) or limit <= 0:
                            continue
                        if not isinstance(observed, (int, float)):
                            continue
                        ratio = observed / limit
                        if worst is None or ratio > worst[0]:
                            worst = (
                                ratio,
                                check.get("name", "unknown"),
                                observed,
                                limit,
                                check.get("unit", ""),
                            )
                status = "PASS" if passed == len(runs) else "FAIL"
                if worst is None:
                    worst_cell = "no configured checks"
                else:
                    _, name, observed, limit, unit = worst
                    worst_cell = f"{name}: {observed:.3g} / {limit:.3g} {unit}"
                print(f"| {p} | {t} | {passed}/{len(runs)} | {worst_cell} | {status} |")

    print("\n## Crypto-symmetric speedup (rsync wall / atp wall; >1 means atp is faster)\n")
    print("Only apples-to-apples pairs are shown: `atp-quic`/`atp-rq` against "
          "`rsync-ssh`, and the plaintext `atp-tcp` control against `rsyncd`.\n")
    pairs = crypto_symmetric_pairs(tools)
    if pairs:
        print("| Payload | " + " | ".join(f"{a} vs {r}" for a, r in pairs) + " |")
        print("|---" * (1 + len(pairs)) + "|")
        for p in payloads:
            cells = []
            for a, r in pairs:
                wa = [x["sender"]["wall_s"] for x in groups.get((p, a), []) if x.get("verify_ok")]
                wr = [x["sender"]["wall_s"] for x in groups.get((p, r), []) if x.get("verify_ok")]
                if wa and wr:
                    cells.append(f"{statistics.mean(wr) / statistics.mean(wa):.2f}x")
                else:
                    cells.append("—")
            print(f"| {p} | " + " | ".join(cells) + " |")
    else:
        print("No crypto-symmetric ATP/rsync pairs were present in the result set.")

    print("\n## Verification\n")
    total = len([r for r in rows if r["run"] != 0])
    ok = len([r for r in rows if r["run"] != 0 and r.get("verify_ok")])
    print(f"- Measured transfers: {total}; bit-for-bit SHA-256 verified: {ok}.")
    if fails:
        print(f"- **{len(fails)} runs FAILED verification or transfer** (including warmups):")
        for f in fails:
            print(f"  - {f['tool']} / {f['payload']} run {f['run']}: "
                  f"status={f['sender'].get('status')} stderr: {f['sender'].get('stderr_head', '')[:200]}")
    else:
        print("- Zero verification failures.")
    guard_failures = [
        r for r in rows
        if r.get("run") != 0
        and isinstance(r.get("resource_guard"), dict)
        and r["resource_guard"].get("ok") is not True
    ]
    if guard_failures:
        print(f"- **{len(guard_failures)} measured runs FAILED the RSS/load resource guard.**")
    elif guard_rows:
        print("- RSS/load resource guard passed for every measured run.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
