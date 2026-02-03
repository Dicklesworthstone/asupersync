#!/usr/bin/env bash
# capture_baseline.sh — Extract benchmark baselines from criterion output.
#
# Usage:
#   ./scripts/capture_baseline.sh                    # capture from latest run
#   ./scripts/capture_baseline.sh --save baselines/  # capture and save to dir
#
# Reads target/criterion/*/new/estimates.json and produces a single JSON
# baseline file with mean/median/p95/p99 for each benchmark.
#
# Prerequisites: jq, cargo bench must have been run at least once.

set -euo pipefail

CRITERION_DIR="${CRITERION_DIR:-target/criterion}"
SAVE_DIR=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --save) SAVE_DIR="$2"; shift 2 ;;
        *) echo "Unknown arg: $1" >&2; exit 1 ;;
    esac
done

if ! command -v jq &>/dev/null; then
    echo "ERROR: jq is required but not installed" >&2
    exit 1
fi
if ! command -v python3 &>/dev/null; then
    echo "ERROR: python3 is required but not installed" >&2
    exit 1
fi

if [[ ! -d "$CRITERION_DIR" ]]; then
    echo "ERROR: No criterion output at $CRITERION_DIR" >&2
    echo "Run 'cargo bench' first to generate benchmark data." >&2
    exit 1
fi

# Build baseline JSON
BASELINES="[]"

find "$CRITERION_DIR" -path '*/new/estimates.json' -type f | sort | while read -r est_file; do
    # Extract benchmark name from path: criterion/<group>/<name>/new/estimates.json
    rel="${est_file#$CRITERION_DIR/}"
    bench_path="${rel%/new/estimates.json}"
    sample_file="${est_file%/estimates.json}/sample.json"

    mean_ns=$(jq -r '.mean.point_estimate' "$est_file")
    median_ns=$(jq -r '.median.point_estimate' "$est_file")
    std_dev=$(jq -r '.std_dev.point_estimate // .median_abs_dev.point_estimate // 0' "$est_file")
    read -r p95_ns p99_ns < <(
        python3 - "$sample_file" <<'PY'
import json
import math
import sys

path = sys.argv[1]
try:
    with open(path, "r") as fh:
        data = json.load(fh)
except FileNotFoundError:
    print("null null")
    sys.exit(0)

iters = data.get("iters", [])
times = data.get("times", [])
values = []
for it, t in zip(iters, times):
    if it:
        values.append(t / it)

if not values:
    print("null null")
    sys.exit(0)

values.sort()

def quantile(p: float) -> float:
    if len(values) == 1:
        return values[0]
    idx = p * (len(values) - 1)
    lo = int(math.floor(idx))
    hi = int(math.ceil(idx))
    if lo == hi:
        return values[lo]
    frac = idx - lo
    return values[lo] * (1 - frac) + values[hi] * frac

print(f"{quantile(0.95)} {quantile(0.99)}")
PY
    )

    jq -n \
        --arg name "$bench_path" \
        --argjson mean "$mean_ns" \
        --argjson median "$median_ns" \
        --argjson p95 "$p95_ns" \
        --argjson p99 "$p99_ns" \
        --argjson std_dev "$std_dev" \
        '{name: $name, mean_ns: $mean, median_ns: $median, p95_ns: $p95, p99_ns: $p99, std_dev_ns: $std_dev}'
done | jq -s '{
    generated_at: (now | todate),
    benchmarks: .
}' > /tmp/asupersync_baseline.json

if [[ -n "$SAVE_DIR" ]]; then
    mkdir -p "$SAVE_DIR"
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    DEST="$SAVE_DIR/baseline_${TIMESTAMP}.json"
    cp /tmp/asupersync_baseline.json "$DEST"
    echo "Baseline saved to: $DEST"

    # Also save as 'latest'
    cp "$DEST" "$SAVE_DIR/baseline_latest.json"
    echo "Also saved as: $SAVE_DIR/baseline_latest.json"
else
    cat /tmp/asupersync_baseline.json
fi
