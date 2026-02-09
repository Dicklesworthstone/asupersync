#!/usr/bin/env bash
# capture_baseline.sh — Extract benchmark baselines from criterion output.
#
# Usage:
#   ./scripts/capture_baseline.sh                    # capture from latest run
#   ./scripts/capture_baseline.sh --save baselines/  # capture and save to dir
#   ./scripts/capture_baseline.sh --run --save baselines/
#   ./scripts/capture_baseline.sh --smoke --seed 3735928559 --save baselines/
#
# Reads target/criterion/*/new/estimates.json and produces a single JSON
# baseline file with mean/median/p95/p99 for each benchmark.
#
# Prerequisites: jq. If using --run/--smoke, cargo bench will be invoked.

set -euo pipefail

CRITERION_DIR="${CRITERION_DIR:-target/criterion}"
SAVE_DIR=""
COMPARE_PATH=""
MAX_REGRESSION_PCT="10"
METRIC="median_ns"
CMD=()
RUN_CMD=0
SMOKE=0
SMOKE_SEED=""

usage() {
    cat <<'USAGE'
Usage: ./scripts/capture_baseline.sh [options]

Options:
  --save <dir>                   Save baseline JSON to directory
  --compare <baseline.json>      Compare against an existing baseline file
  --max-regression-pct <pct>     Regression threshold (default: 10)
  --metric <mean_ns|median_ns|p95_ns|p99_ns> Metric to compare (default: median_ns)
  --cmd "<command>"              Command to run for --run/--smoke
  --run                          Run benchmark command before capture
  --smoke                        Run benchmark + capture + smoke report
  --seed <value>                 Set ASUPERSYNC_SEED for --run/--smoke
  -h, --help                     Show help

Examples:
  ./scripts/capture_baseline.sh
  ./scripts/capture_baseline.sh --save baselines/
  ./scripts/capture_baseline.sh --run --save baselines/
  ./scripts/capture_baseline.sh --smoke --seed 3735928559 --save baselines/
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --save) SAVE_DIR="$2"; shift 2 ;;
        --compare) COMPARE_PATH="$2"; shift 2 ;;
        --max-regression-pct) MAX_REGRESSION_PCT="$2"; shift 2 ;;
        --metric) METRIC="$2"; shift 2 ;;
        --cmd) CMD=($2); shift 2 ;;
        --run) RUN_CMD=1; shift ;;
        --smoke) SMOKE=1; RUN_CMD=1; shift ;;
        --seed) SMOKE_SEED="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown arg: $1" >&2; usage; exit 1 ;;
    esac
done

if [[ ${#CMD[@]} -eq 0 ]]; then
    CMD=(cargo bench --bench phase0_baseline)
fi

if ! command -v jq &>/dev/null; then
    echo "ERROR: jq is required but not installed" >&2
    exit 1
fi
if ! command -v python3 &>/dev/null; then
    echo "ERROR: python3 is required but not installed" >&2
    exit 1
fi

if [[ "$SMOKE" -eq 1 && -z "$SAVE_DIR" ]]; then
    SAVE_DIR="baselines"
fi

# Run the command if requested (smoke runs always do this).
if [[ "$RUN_CMD" -eq 1 ]]; then
    if [[ -n "$SMOKE_SEED" ]]; then
        export ASUPERSYNC_SEED="$SMOKE_SEED"
    fi

    RUN_SEED="${ASUPERSYNC_SEED:-}"
    RUN_SEED_FMT="$RUN_SEED"
    if [[ -n "$RUN_SEED" ]]; then
        RUN_SEED_FMT="$RUN_SEED"
    fi

    printf '{"event":"profiling_run_start","command":"%s","seed":"%s"}\n' "${CMD[*]}" "$RUN_SEED_FMT"
    "${CMD[@]}"
    printf '{"event":"profiling_run_end","command":"%s","seed":"%s"}\n' "${CMD[*]}" "$RUN_SEED_FMT"
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

if [[ -n "$COMPARE_PATH" ]]; then
    python3 - "$COMPARE_PATH" "$METRIC" "$MAX_REGRESSION_PCT" <<'PY'
import json
import sys

baseline_path = sys.argv[1]
metric = sys.argv[2]
max_regression_pct = float(sys.argv[3])

with open("/tmp/asupersync_baseline.json", "r") as fh:
    current = json.load(fh)
with open(baseline_path, "r") as fh:
    baseline = json.load(fh)

def index_by_name(payload):
    return {entry["name"]: entry for entry in payload.get("benchmarks", [])}

current_map = index_by_name(current)
baseline_map = index_by_name(baseline)

regressions = []
warnings = []

for name, cur in current_map.items():
    base = baseline_map.get(name)
    if base is None:
        warnings.append(f"missing_baseline:{name}")
        continue
    cur_val = cur.get(metric)
    base_val = base.get(metric)
    if not isinstance(cur_val, (int, float)) or not isinstance(base_val, (int, float)) or base_val <= 0:
        warnings.append(f"invalid_metric:{name}")
        continue
    ratio = cur_val / base_val
    delta_pct = (ratio - 1.0) * 100.0
    if delta_pct > max_regression_pct:
        regressions.append((name, base_val, cur_val, delta_pct))

for name in baseline_map:
    if name not in current_map:
        warnings.append(f"missing_current:{name}")

if warnings:
    print("Warnings:")
    for w in sorted(set(warnings)):
        print(f"  - {w}")

if regressions:
    print(f"Regressions (>{max_regression_pct:.2f}% on {metric}):")
    for name, base_val, cur_val, delta_pct in sorted(regressions, key=lambda x: x[3], reverse=True):
        print(f"  - {name}: {base_val:.2f} -> {cur_val:.2f} (+{delta_pct:.2f}%)")
    sys.exit(2)

print("No regressions detected.")
PY
fi

if [[ -n "$SAVE_DIR" ]]; then
    mkdir -p "$SAVE_DIR"
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    DEST="$SAVE_DIR/baseline_${TIMESTAMP}.json"
    cp /tmp/asupersync_baseline.json "$DEST"
    echo "Baseline saved to: $DEST"

    # Also save as 'latest'
    cp "$DEST" "$SAVE_DIR/baseline_latest.json"
    echo "Also saved as: $SAVE_DIR/baseline_latest.json"

    if [[ "$SMOKE" -eq 1 ]]; then
        SMOKE_REPORT="$SAVE_DIR/smoke_report_${TIMESTAMP}.json"
        python3 - <<PY > "$SMOKE_REPORT"
import json
import os
import platform
import subprocess
import time

def git_sha():
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    except Exception:
        return None

report = {
    "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "command": "${CMD[*]}",
    "seed": os.environ.get("ASUPERSYNC_SEED"),
    "criterion_dir": "${CRITERION_DIR}",
    "baseline_path": "$DEST",
    "latest_path": "${SAVE_DIR}/baseline_latest.json",
    "git_sha": git_sha(),
    "config": {
        "criterion_dir": "${CRITERION_DIR}",
        "save_dir": "${SAVE_DIR}" or None,
        "compare_path": "${COMPARE_PATH}" or None,
        "metric": "${METRIC}",
        "max_regression_pct": float("${MAX_REGRESSION_PCT}"),
    },
    "env": {
        "CI": os.environ.get("CI"),
        "RUSTFLAGS": os.environ.get("RUSTFLAGS"),
    },
    "system": {
        "os": platform.system().lower(),
        "arch": platform.machine(),
        "platform": platform.platform(),
    },
}

print(json.dumps(report, indent=2))
PY
        echo "Smoke report saved to: $SMOKE_REPORT"
    fi
else
    cat /tmp/asupersync_baseline.json
fi
