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
# Prerequisites: jq. If using --run/--smoke without --cmd/--cmd-b64, benchmark
# execution requires rch via RCH_BIN and will fail closed rather than running a
# local cargo bench fallback. Cold full release-perf sweeps can exceed rch's
# default 1200s command timeout, so the default benchmark path passes
# RCH_BUILD_TIMEOUT_SEC=5400 unless the caller already set a different value.

set -euo pipefail

CRITERION_DIR="${CRITERION_DIR:-target/criterion}"
SAVE_DIR=""
COMPARE_PATH=""
MAX_REGRESSION_PCT="10"
METRIC="median_ns"
CMD=()
CMD_STRING=""
CMD_B64=""
RUN_CMD=0
SMOKE=0
SMOKE_SEED=""
RCH_BIN="${RCH_BIN:-rch}"
RCH_TARGET_DIR="${RCH_TARGET_DIR:-${TMPDIR:-/tmp}/rch_target_capture_baseline_phase0}"
RCH_BUILD_TIMEOUT_SEC="${RCH_BUILD_TIMEOUT_SEC:-5400}"
RUN_OUTPUT_LOG="${RUN_OUTPUT_LOG:-${TMPDIR:-/tmp}/asupersync_capture_baseline_run_$$.log}"
BASELINE_TMP_PATH="${BASELINE_TMP_PATH:-${TMPDIR:-/tmp}/asupersync_baseline_$$.json}"
BENCH_CARGO_PROFILE="${BENCH_CARGO_PROFILE:-release-perf}"
BENCH_FEATURES="${BENCH_FEATURES:-criterion-benches}"
BENCH_RUSTFLAGS="${BENCH_RUSTFLAGS:--C force-frame-pointers=yes}"
# gauntlet PERF-001/002/003: append-only ratchet substrate + measured profile.
BENCH_HISTORY_DIR="${BENCH_HISTORY_DIR:-.bench-history}"
BENCH_PROFILE="${BENCH_PROFILE:-}"
WRITE_BENCH_HISTORY="${WRITE_BENCH_HISTORY:-0}"
CV_PCT_FLAKE_THRESHOLD="${CV_PCT_FLAKE_THRESHOLD:-5.0}"
SWARM_LEDGER_DIR="${SWARM_LEDGER_DIR:-artifacts/swarm-perf-ledger}"
SWARM_LEDGER_SCENARIO_ID="${SWARM_LEDGER_SCENARIO_ID:-criterion-release-perf}"
WRITE_SWARM_LEDGER="${WRITE_SWARM_LEDGER:-0}"

usage() {
    cat <<'USAGE'
Usage: ./scripts/capture_baseline.sh [options]

Options:
  --save <dir>                   Save baseline JSON to directory
  --compare <baseline.json>      Compare against an existing baseline file
  --max-regression-pct <pct>     Regression threshold (default: 10)
  --metric <mean_ns|median_ns|p95_ns|p99_ns> Metric to compare (default: median_ns)
  --cmd "<command>"              Command to run for --run/--smoke
  --cmd=<command>                Same as --cmd; useful when wrappers split quoted args
  --cmd-b64 <base64>             Base64-encoded command string for wrapper-safe transport
  --run                          Run benchmark command before capture
  --smoke                        Run benchmark + capture + smoke report
  --seed <value>                 Set ASUPERSYNC_SEED for --run/--smoke
  --profile <name>               Profile label recorded in bench-history records
  --cargo-profile <name>         Cargo profile for default benchmark runs (default: release-perf)
  --bench-features <features>    Cargo features for default benchmark runs (default: criterion-benches)
  --bench-rustflags <flags>      RUSTFLAGS for default benchmark runs (default: -C force-frame-pointers=yes)
  --bench-history                Write latest JSON files plus runs.jsonl to bench-history dir
  --no-bench-history             Disable bench-history writes, overriding env defaults
  --bench-history-dir <dir>      Bench-history output dir (default: .bench-history)
  --cv-pct-flake-threshold <pct> Mark benchmarks with cv_pct above this threshold (default: 5.0)
  --swarm-ledger                 Append records to the swarm performance ledger
  --no-swarm-ledger              Disable swarm performance ledger writes, overriding env defaults
  --swarm-ledger-dir <dir>       Swarm ledger output dir (default: artifacts/swarm-perf-ledger)
  --scenario-id <id>             Scenario id recorded in swarm ledger records
  -h, --help                     Show help

Examples:
  ./scripts/capture_baseline.sh
  ./scripts/capture_baseline.sh --save baselines/
  ./scripts/capture_baseline.sh --run --save baselines/
  ./scripts/capture_baseline.sh --smoke --seed 3735928559 --save baselines/
  ./scripts/capture_baseline.sh --bench-history --profile release-perf
  ./scripts/capture_baseline.sh --swarm-ledger --scenario-id scheduler-global-queue

Environment:
  RCH_BUILD_TIMEOUT_SEC          Timeout passed to default rch benchmark runs (default: 5400)
USAGE
}

require_arg() {
    local opt="$1"
    local value="${2:-}"
    if [[ -z "$value" ]]; then
        echo "ERROR: $opt requires a non-empty value" >&2
        usage >&2
        exit 1
    fi
}

require_rch_for_default_benchmark_run() {
    if ! command -v "$RCH_BIN" >/dev/null 2>&1; then
        echo "ERROR: benchmark execution requires RCH_BIN ('$RCH_BIN') to resolve to a working rch executable; refusing local cargo bench fallback." >&2
        exit 1
    fi
}

reject_rch_local_fallback_log() {
    if grep -Eq '^\[RCH\] local \(|falling back to local' "$RUN_OUTPUT_LOG" 2>/dev/null; then
        echo "ERROR: rch local fallback detected; refusing local cargo execution." >&2
        echo "rch local fallback detected; refusing local cargo execution" > "${RUN_OUTPUT_LOG}.rch_local_fallback"
        exit 86
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --save) require_arg "$1" "${2:-}"; SAVE_DIR="$2"; shift 2 ;;
        --save=*) SAVE_DIR="${1#--save=}"; require_arg "--save" "$SAVE_DIR"; shift ;;
        --compare) require_arg "$1" "${2:-}"; COMPARE_PATH="$2"; shift 2 ;;
        --compare=*) COMPARE_PATH="${1#--compare=}"; require_arg "--compare" "$COMPARE_PATH"; shift ;;
        --max-regression-pct) require_arg "$1" "${2:-}"; MAX_REGRESSION_PCT="$2"; shift 2 ;;
        --max-regression-pct=*) MAX_REGRESSION_PCT="${1#--max-regression-pct=}"; require_arg "--max-regression-pct" "$MAX_REGRESSION_PCT"; shift ;;
        --metric) require_arg "$1" "${2:-}"; METRIC="$2"; shift 2 ;;
        --metric=*) METRIC="${1#--metric=}"; require_arg "--metric" "$METRIC"; shift ;;
        --cmd) require_arg "$1" "${2:-}"; CMD_STRING="$2"; shift 2 ;;
        --cmd=*) CMD_STRING="${1#--cmd=}"; require_arg "--cmd" "$CMD_STRING"; shift ;;
        --cmd-b64) require_arg "$1" "${2:-}"; CMD_B64="$2"; shift 2 ;;
        --cmd-b64=*) CMD_B64="${1#--cmd-b64=}"; require_arg "--cmd-b64" "$CMD_B64"; shift ;;
        --run) RUN_CMD=1; shift ;;
        --smoke) SMOKE=1; RUN_CMD=1; shift ;;
        --profile) require_arg "$1" "${2:-}"; BENCH_PROFILE="$2"; shift 2 ;;
        --profile=*) BENCH_PROFILE="${1#--profile=}"; require_arg "--profile" "$BENCH_PROFILE"; shift ;;
        --cargo-profile) require_arg "$1" "${2:-}"; BENCH_CARGO_PROFILE="$2"; shift 2 ;;
        --cargo-profile=*) BENCH_CARGO_PROFILE="${1#--cargo-profile=}"; require_arg "--cargo-profile" "$BENCH_CARGO_PROFILE"; shift ;;
        --bench-features) require_arg "$1" "${2:-}"; BENCH_FEATURES="$2"; shift 2 ;;
        --bench-features=*) BENCH_FEATURES="${1#--bench-features=}"; require_arg "--bench-features" "$BENCH_FEATURES"; shift ;;
        --bench-rustflags) require_arg "$1" "${2:-}"; BENCH_RUSTFLAGS="$2"; shift 2 ;;
        --bench-rustflags=*) BENCH_RUSTFLAGS="${1#--bench-rustflags=}"; require_arg "--bench-rustflags" "$BENCH_RUSTFLAGS"; shift ;;
        --bench-history) WRITE_BENCH_HISTORY=1; shift ;;
        --no-bench-history) WRITE_BENCH_HISTORY=0; shift ;;
        --bench-history-dir) require_arg "$1" "${2:-}"; BENCH_HISTORY_DIR="$2"; shift 2 ;;
        --bench-history-dir=*) BENCH_HISTORY_DIR="${1#--bench-history-dir=}"; require_arg "--bench-history-dir" "$BENCH_HISTORY_DIR"; shift ;;
        --cv-pct-flake-threshold) require_arg "$1" "${2:-}"; CV_PCT_FLAKE_THRESHOLD="$2"; shift 2 ;;
        --cv-pct-flake-threshold=*) CV_PCT_FLAKE_THRESHOLD="${1#--cv-pct-flake-threshold=}"; require_arg "--cv-pct-flake-threshold" "$CV_PCT_FLAKE_THRESHOLD"; shift ;;
        --swarm-ledger) WRITE_SWARM_LEDGER=1; shift ;;
        --no-swarm-ledger) WRITE_SWARM_LEDGER=0; shift ;;
        --swarm-ledger-dir) require_arg "$1" "${2:-}"; SWARM_LEDGER_DIR="$2"; shift 2 ;;
        --swarm-ledger-dir=*) SWARM_LEDGER_DIR="${1#--swarm-ledger-dir=}"; require_arg "--swarm-ledger-dir" "$SWARM_LEDGER_DIR"; shift ;;
        --scenario-id) require_arg "$1" "${2:-}"; SWARM_LEDGER_SCENARIO_ID="$2"; shift 2 ;;
        --scenario-id=*) SWARM_LEDGER_SCENARIO_ID="${1#--scenario-id=}"; require_arg "--scenario-id" "$SWARM_LEDGER_SCENARIO_ID"; shift ;;
        --seed) require_arg "$1" "${2:-}"; SMOKE_SEED="$2"; shift 2 ;;
        --seed=*) SMOKE_SEED="${1#--seed=}"; require_arg "--seed" "$SMOKE_SEED"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown arg: $1" >&2; usage; exit 1 ;;
    esac
done

if [[ -z "$BENCH_PROFILE" ]]; then
    BENCH_PROFILE="$BENCH_CARGO_PROFILE"
fi

if [[ -n "$CMD_B64" ]]; then
    if ! command -v base64 &>/dev/null; then
        echo "ERROR: base64 is required when using --cmd-b64" >&2
        exit 1
    fi
    CMD_STRING="$(printf '%s' "$CMD_B64" | base64 --decode)"
fi

if [[ -z "$CMD_STRING" ]]; then
    export RCH_BUILD_TIMEOUT_SEC
    CMD=(
        "$RCH_BIN" exec -- env
        "RCH_BUILD_TIMEOUT_SEC=${RCH_BUILD_TIMEOUT_SEC}"
        "RUSTFLAGS=${BENCH_RUSTFLAGS}"
        "CARGO_TARGET_DIR=${RCH_TARGET_DIR}"
        cargo bench --profile "$BENCH_CARGO_PROFILE" --features "$BENCH_FEATURES" --bench phase0_baseline
    )
fi

if ! command -v jq &>/dev/null; then
    echo "ERROR: jq is required but not installed" >&2
    exit 1
fi
if ! command -v python3 &>/dev/null; then
    echo "ERROR: python3 is required but not installed" >&2
    exit 1
fi
case "$WRITE_BENCH_HISTORY" in
    0|1) ;;
    *)
        echo "ERROR: WRITE_BENCH_HISTORY must be 0 or 1" >&2
        exit 1
        ;;
esac
case "$WRITE_SWARM_LEDGER" in
    0|1) ;;
    *)
        echo "ERROR: WRITE_SWARM_LEDGER must be 0 or 1" >&2
        exit 1
        ;;
esac
python3 - "$CV_PCT_FLAKE_THRESHOLD" <<'PY'
import math
import sys

try:
    threshold = float(sys.argv[1])
except ValueError:
    print("ERROR: --cv-pct-flake-threshold must be a finite non-negative number", file=sys.stderr)
    raise SystemExit(1)

if not math.isfinite(threshold) or threshold < 0:
    print("ERROR: --cv-pct-flake-threshold must be a finite non-negative number", file=sys.stderr)
    raise SystemExit(1)
PY

json_escape() {
    jq -Rn --arg s "$1" '$s'
}

if [[ "$SMOKE" -eq 1 && -z "$SAVE_DIR" ]]; then
    SAVE_DIR="baselines"
fi

# Run the command if requested (smoke runs always do this).
if [[ "$RUN_CMD" -eq 1 ]]; then
    if [[ -n "$SMOKE_SEED" ]]; then
        export ASUPERSYNC_SEED="$SMOKE_SEED"
    fi

    if [[ -z "$CMD_STRING" ]]; then
        require_rch_for_default_benchmark_run
    fi

    RUN_SEED="${ASUPERSYNC_SEED:-}"
    RUN_SEED_FMT="$RUN_SEED"
    if [[ -n "$RUN_SEED" ]]; then
        RUN_SEED_FMT="$RUN_SEED"
    fi

    if [[ -n "$CMD_STRING" ]]; then
        RUN_COMMAND_DISPLAY="$CMD_STRING"
    else
        RUN_COMMAND_DISPLAY="${CMD[*]}"
    fi
    printf '{"event":"profiling_run_start","command":%s,"seed":%s}\n' \
        "$(json_escape "$RUN_COMMAND_DISPLAY")" \
        "$(json_escape "$RUN_SEED_FMT")"
    if [[ -n "$CMD_STRING" ]]; then
        # Preserve shell quoting without pulling in login/startup-file noise.
        if BASH_ENV='' "${BASH:-bash}" -c "$CMD_STRING" 2>&1 | tee "$RUN_OUTPUT_LOG"; then
            reject_rch_local_fallback_log
        else
            reject_rch_local_fallback_log
            exit 1
        fi
    else
        if "${CMD[@]}" 2>&1 | tee "$RUN_OUTPUT_LOG"; then
            reject_rch_local_fallback_log
        else
            reject_rch_local_fallback_log
            exit 1
        fi
    fi
    printf '{"event":"profiling_run_end","command":%s,"seed":%s}\n' \
        "$(json_escape "$RUN_COMMAND_DISPLAY")" \
        "$(json_escape "$RUN_SEED_FMT")"
fi

if [[ ! -d "$CRITERION_DIR" ]]; then
    echo "ERROR: No criterion output at $CRITERION_DIR" >&2
    echo "Run 'cargo bench' first to generate benchmark data." >&2
    exit 1
fi

find "$CRITERION_DIR" -path '*/new/estimates.json' -type f | sort | while read -r est_file; do
    # Extract benchmark name from path: criterion/<group>/<name>/new/estimates.json
    rel="${est_file#"$CRITERION_DIR"/}"
    bench_path="${rel%/new/estimates.json}"
    sample_file="${est_file%/estimates.json}/sample.json"

    mean_ns=$(jq -r '.mean.point_estimate' "$est_file")
    median_ns=$(jq -r '.median.point_estimate' "$est_file")
    std_dev=$(jq -r '.std_dev.point_estimate // .median_abs_dev.point_estimate // 0' "$est_file")
    read -r p95_ns p99_ns sample_count < <(
        python3 - "$sample_file" <<'PY'
import json
import math
import sys

path = sys.argv[1]
try:
    with open(path, "r") as fh:
        data = json.load(fh)
except FileNotFoundError:
    print("null null 0")
    sys.exit(0)

iters = data.get("iters", [])
times = data.get("times", [])
values = []
for it, t in zip(iters, times):
    if it:
        values.append(t / it)

if not values:
    print("null null 0")
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

print(f"{quantile(0.95)} {quantile(0.99)} {len(values)}")
PY
    )

    jq -n \
        --arg name "$bench_path" \
        --argjson mean "$mean_ns" \
        --argjson median "$median_ns" \
        --argjson p95 "$p95_ns" \
        --argjson p99 "$p99_ns" \
        --argjson std_dev "$std_dev" \
        --argjson sample_count "$sample_count" \
        '{name: $name, mean_ns: $mean, median_ns: $median, p95_ns: $p95, p99_ns: $p99, std_dev_ns: $std_dev,
          cv_pct: (if (($mean // 0) > 0) then (($std_dev / $mean) * 100) else null end),
          sample_count: $sample_count}'
done | jq -s --argjson flake_threshold "$CV_PCT_FLAKE_THRESHOLD" '{
    schema_version: "asupersync.baseline.v2",
    generated_at: (now | todate),
    cv_pct_flake_threshold: $flake_threshold,
    flaky_benches: [.[] | select((.cv_pct // 0) > $flake_threshold) | .name],
    benchmarks: .
}' > "$BASELINE_TMP_PATH"

if [[ -n "$COMPARE_PATH" ]]; then
    python3 - "$BASELINE_TMP_PATH" "$COMPARE_PATH" "$METRIC" "$MAX_REGRESSION_PCT" <<'PY'
import json
import sys

current_path = sys.argv[1]
baseline_path = sys.argv[2]
metric = sys.argv[3]
max_regression_pct = float(sys.argv[4])

with open(current_path, "r") as fh:
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
    cp "$BASELINE_TMP_PATH" "$DEST"
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
        "cargo_profile": "${BENCH_CARGO_PROFILE}",
        "bench_rustflags": "${BENCH_RUSTFLAGS}",
        "rch_build_timeout_sec": "${RCH_BUILD_TIMEOUT_SEC}",
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
    cat "$BASELINE_TMP_PATH"
fi

# gauntlet PERF-001: populate the append-only .bench-history ratchet substrate.
# One <bench>.latest.json per benchmark (the committed keep-gate baseline) plus a
# runs.jsonl append. Each record carries git_sha + profile + cv_pct for the
# pass-over-pass ratchet (apply-ratchet.sh, PERF-004) to consume.
if [[ "$WRITE_BENCH_HISTORY" -eq 1 ]]; then
    BASELINE_TMP_PATH="$BASELINE_TMP_PATH" BENCH_HISTORY_DIR="$BENCH_HISTORY_DIR" BENCH_PROFILE="$BENCH_PROFILE" python3 - <<'PY'
import json, os, re, subprocess, sys, time

baseline_path = os.environ.get("BASELINE_TMP_PATH")
hist = os.environ.get("BENCH_HISTORY_DIR", ".bench-history")
profile = os.environ.get("BENCH_PROFILE", "unknown")
try:
    with open(baseline_path) as fh:
        data = json.load(fh)
except FileNotFoundError:
    raise SystemExit(0)

os.makedirs(hist, exist_ok=True)

def git_sha():
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    except Exception:
        return None

sha = git_sha()
ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
runs_path = os.path.join(hist, "runs.jsonl")
n = 0
with open(runs_path, "a") as runs:
    for b in data.get("benchmarks", []):
        name = b.get("name", "")
        safe = re.sub(r"[^A-Za-z0-9._-]", "__", name)
        rec = {
            "name": name, "git_sha": sha, "profile": profile, "generated_at": ts,
            "mean_ns": b.get("mean_ns"), "median_ns": b.get("median_ns"),
            "p95_ns": b.get("p95_ns"), "p99_ns": b.get("p99_ns"),
            "std_dev_ns": b.get("std_dev_ns"), "cv_pct": b.get("cv_pct"),
        }
        with open(os.path.join(hist, f"{safe}.latest.json"), "w") as f:
            json.dump(rec, f, indent=2, sort_keys=True)
        runs.write(json.dumps(rec, sort_keys=True) + "\n")
        n += 1
print(f".bench-history updated: {hist} ({n} benches, profile={profile}, sha={sha})", file=sys.stderr)
PY
fi

# br-asupersync-vssefs.4: durable, append-only p95/p99/CV ledger for swarm
# pressure evidence. This intentionally complements .bench-history: history
# remains the certification ratchet, while the swarm ledger captures richer
# RCH/scenario provenance for cross-commit pressure-lab comparisons.
if [[ "$WRITE_SWARM_LEDGER" -eq 1 ]]; then
    BASELINE_TMP_PATH="$BASELINE_TMP_PATH" \
    SWARM_LEDGER_DIR="$SWARM_LEDGER_DIR" \
    SWARM_LEDGER_SCENARIO_ID="$SWARM_LEDGER_SCENARIO_ID" \
    BENCH_PROFILE="$BENCH_PROFILE" \
    BENCH_CARGO_PROFILE="$BENCH_CARGO_PROFILE" \
    BENCH_FEATURES="$BENCH_FEATURES" \
    SMOKE_SEED="$SMOKE_SEED" \
    CRITERION_DIR="$CRITERION_DIR" \
    RUN_OUTPUT_LOG="$RUN_OUTPUT_LOG" \
    RUN_COMMAND_DISPLAY="${RUN_COMMAND_DISPLAY:-}" \
    python3 - <<'PY'
import datetime as dt
import json
import math
import os
import platform
import re
import socket
import subprocess
import sys

SCHEMA_VERSION = "asupersync.swarm-performance-ledger.v1"


def fail(message: str) -> None:
    print(f"ERROR: swarm ledger {message}", file=sys.stderr)
    raise SystemExit(1)


def env_first(*names):
    for name in names:
        value = os.environ.get(name)
        if value:
            return value
    return None


def git_sha() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    except Exception as exc:
        fail(f"requires current git commit metadata: {exc}")


def parse_utc(value: str) -> dt.datetime:
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        fail(f"timestamp {value!r} is not RFC3339/ISO-8601: {exc}")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def now_utc() -> str:
    override = os.environ.get("SWARM_LEDGER_GENERATED_AT")
    if override:
        parse_utc(override)
        return override
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def finite_number(record: dict, field: str) -> float:
    value = record.get(field)
    if not isinstance(value, (int, float)) or not math.isfinite(value):
        fail(f"record for {record.get('name')!r} is missing finite {field}")
    return float(value)


def positive_sample_count(record: dict) -> int:
    value = record.get("sample_count")
    if not isinstance(value, int) or value <= 0:
        fail(f"record for {record.get('name')!r} is missing positive sample_count")
    return value


def optional_nonnegative_int(name: str):
    value = os.environ.get(name)
    if value is None or value == "":
        return None
    if not re.fullmatch(r"[0-9]+", value):
        fail(f"{name} must be a non-negative integer")
    return int(value)


def validate_scenario_id(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}", value):
        fail("--scenario-id must be 1-128 chars of letters, digits, '.', '_', ':', '/', or '-'")
    return value


def parse_rch_log_provenance() -> dict:
    path = os.environ.get("RUN_OUTPUT_LOG")
    if not path:
        return {}
    try:
        with open(path, "r", errors="replace") as fh:
            text = fh.read()
    except FileNotFoundError:
        return {}
    result = {}
    worker = re.search(r"Selected worker:\s+([A-Za-z0-9][A-Za-z0-9._:-]{0,127})\b", text)
    if worker:
        result["worker_id"] = worker.group(1)
    build = re.search(r"\.rch-target-[A-Za-z0-9._:-]+-job-([0-9]+)-", text)
    if build:
        result["build_id"] = build.group(1)
    return result


def validate_rch_provenance() -> dict:
    parsed = parse_rch_log_provenance()
    worker_id = env_first("SWARM_LEDGER_RCH_WORKER_ID", "RCH_WORKER_ID", "RCH_WORKER")
    build_id = env_first("SWARM_LEDGER_RCH_BUILD_ID", "RCH_BUILD_ID", "RCH_BUILD")
    command = env_first("SWARM_LEDGER_RCH_COMMAND", "RCH_COMMAND", "RUN_COMMAND_DISPLAY")
    worker_id = worker_id or parsed.get("worker_id")
    build_id = build_id or parsed.get("build_id")
    if not worker_id or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", worker_id):
        fail("requires valid RCH worker id via env or RUN_OUTPUT_LOG")
    if not build_id or not re.fullmatch(r"[0-9]+", build_id):
        fail("requires numeric RCH build id via env or RUN_OUTPUT_LOG")
    return {
        "worker_id": worker_id,
        "build_id": build_id,
        "command": command,
        "remote_required": os.environ.get("RCH_REQUIRE_REMOTE") == "1",
        "run_output_log": os.environ.get("RUN_OUTPUT_LOG"),
    }


baseline_path = os.environ["BASELINE_TMP_PATH"]
ledger_dir = os.environ.get("SWARM_LEDGER_DIR", "artifacts/swarm-perf-ledger")
scenario_id = validate_scenario_id(os.environ.get("SWARM_LEDGER_SCENARIO_ID", "criterion-release-perf"))
generated_at = now_utc()
generated_dt = parse_utc(generated_at)
sha = git_sha()
expected_sha = os.environ.get("SWARM_LEDGER_EXPECT_GIT_SHA")
if expected_sha and expected_sha != sha:
    fail(f"stale commit metadata: expected {expected_sha}, current HEAD is {sha}")

memory_envelope_bytes = optional_nonnegative_int("SWARM_LEDGER_MEMORY_ENVELOPE_BYTES")
max_rss_bytes = optional_nonnegative_int("SWARM_LEDGER_MAX_RSS_BYTES")
if memory_envelope_bytes is None and max_rss_bytes is None:
    fail("requires SWARM_LEDGER_MEMORY_ENVELOPE_BYTES or SWARM_LEDGER_MAX_RSS_BYTES")

quiescence_verdict = os.environ.get("SWARM_LEDGER_QUIESCENCE_VERDICT", "not_applicable")
if quiescence_verdict not in {"pass", "fail", "not_applicable"}:
    fail("SWARM_LEDGER_QUIESCENCE_VERDICT must be pass, fail, or not_applicable")

verdict = os.environ.get("SWARM_LEDGER_VERDICT", "pass")
if verdict not in {"pass", "fail"}:
    fail("SWARM_LEDGER_VERDICT must be pass or fail")

rch = validate_rch_provenance()
with open(baseline_path, "r") as fh:
    baseline = json.load(fh)

os.makedirs(ledger_dir, exist_ok=True)
ledger_path = os.path.join(ledger_dir, "ledger.jsonl")

if os.path.exists(ledger_path):
    with open(ledger_path, "r") as existing:
        for line_no, line in enumerate(existing, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                previous = json.loads(line)
            except json.JSONDecodeError as exc:
                fail(f"existing ledger line {line_no} is malformed JSON: {exc}")
            previous_ts = previous.get("generated_at")
            if not isinstance(previous_ts, str):
                fail(f"existing ledger line {line_no} is missing generated_at")
            if parse_utc(previous_ts) > generated_dt:
                fail(
                    f"non-monotonic history timestamp: existing {previous_ts} is newer than {generated_at}"
                )

features = os.environ.get("BENCH_FEATURES", "")
feature_set = [part for part in re.split(r"[,\s]+", features) if part]
seed = env_first("SWARM_LEDGER_SEED", "SMOKE_SEED", "ASUPERSYNC_SEED")
profile = os.environ.get("BENCH_PROFILE") or os.environ.get("BENCH_CARGO_PROFILE") or "unknown"
host = socket.gethostname()

records = []
for bench in baseline.get("benchmarks", []):
    name = bench.get("name")
    if not isinstance(name, str) or not name:
        fail("benchmark record is missing non-empty name")
    p50_ns = finite_number(bench, "median_ns")
    p95_ns = finite_number(bench, "p95_ns")
    p99_ns = finite_number(bench, "p99_ns")
    cv_pct = finite_number(bench, "cv_pct")
    sample_count = positive_sample_count(bench)
    if not (p50_ns <= p95_ns <= p99_ns):
        fail(f"record for {name!r} has non-monotonic p50/p95/p99 latencies")
    throughput = 1_000_000_000.0 / p50_ns if p50_ns > 0 else None
    if throughput is None or not math.isfinite(throughput):
        fail(f"record for {name!r} cannot derive finite throughput_ops_per_sec")

    records.append(
        {
            "schema_version": SCHEMA_VERSION,
            "record_id": f"{sha}:{scenario_id}:{name}:{generated_at}",
            "generated_at": generated_at,
            "git_sha": sha,
            "scenario_id": scenario_id,
            "benchmark_name": name,
            "seed": seed,
            "sample_count": sample_count,
            "cargo_profile": profile,
            "cargo_features": features,
            "feature_set": feature_set,
            "criterion_dir": os.environ.get("CRITERION_DIR"),
            "latency_ns": {
                "p50": p50_ns,
                "p95": p95_ns,
                "p99": p99_ns,
            },
            "cv_pct": cv_pct,
            "throughput_ops_per_sec": throughput,
            "memory": {
                "max_rss_bytes": max_rss_bytes,
                "memory_envelope_bytes": memory_envelope_bytes,
            },
            "quiescence": {
                "verdict": quiescence_verdict,
            },
            "rch": rch,
            "machine": {
                "hostname": host,
                "platform": platform.platform(),
                "arch": platform.machine(),
            },
            "verdict": verdict,
        }
    )

if not records:
    fail("baseline contains no benchmark records")

with open(ledger_path, "a") as ledger:
    for record in records:
        ledger.write(json.dumps(record, sort_keys=True) + "\n")

print(
    "swarm performance ledger updated: "
    f"{ledger_path} ({len(records)} records, schema={SCHEMA_VERSION}, scenario={scenario_id}, "
    f"sha={sha}, rch_worker={rch['worker_id']}, rch_build={rch['build_id']})",
    file=sys.stderr,
)
PY
fi
