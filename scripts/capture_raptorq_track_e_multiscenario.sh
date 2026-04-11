#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

BENCH_FILTER="${BENCH_FILTER:-RQ-E-GF256-DUAL}"
SAMPLE_SIZE="${SAMPLE_SIZE:-40}"
WARM_UP_TIME="${WARM_UP_TIME:-0.2}"
MEASUREMENT_TIME="${MEASUREMENT_TIME:-0.2}"
TARGET_ROOT="${TARGET_ROOT:-/tmp/rch-e5-long-v5}"

cd "$PROJECT_ROOT"

run_case() {
    local name="$1"
    shift

    local target_dir="${TARGET_ROOT}-${name}"
    local capture_file="/tmp/asupersync-${name}.baseline.json"
    local log_file="/tmp/asupersync-${name}.remote.log"

    env "$@" \
        CARGO_TARGET_DIR="$target_dir" \
        cargo bench --bench raptorq_benchmark --features simd-intrinsics -- \
        "$BENCH_FILTER" \
        --sample-size "$SAMPLE_SIZE" \
        --warm-up-time "$WARM_UP_TIME" \
        --measurement-time "$MEASUREMENT_TIME" \
        >"$log_file" 2>&1

    CRITERION_DIR="$target_dir/criterion" ./scripts/capture_baseline.sh >"$capture_file"
}

run_case \
    baseline \
    ASUPERSYNC_GF256_PROFILE_PACK=scalar-conservative-v1 \
    ASUPERSYNC_GF256_DUAL_POLICY=never

run_case \
    auto \
    ASUPERSYNC_GF256_PROFILE_PACK=auto \
    ASUPERSYNC_GF256_DUAL_POLICY=auto

run_case \
    rollback \
    ASUPERSYNC_GF256_PROFILE_PACK=auto \
    ASUPERSYNC_GF256_DUAL_POLICY=auto \
    ASUPERSYNC_GF256_DUAL_MUL_MIN_TOTAL=32768 \
    ASUPERSYNC_GF256_DUAL_MUL_MAX_TOTAL=32768

python3 - <<'PY'
import json
from pathlib import Path

BENCH_FILTER = "RQ-E-GF256-DUAL"


def load_case(name: str):
    payload = json.loads(Path(f"/tmp/asupersync-{name}.baseline.json").read_text())
    benchmarks = [
        entry
        for entry in payload["benchmarks"]
        if BENCH_FILTER in entry["name"]
    ]
    return {
        "benchmark_count": len(benchmarks),
        "benchmarks": benchmarks,
    }


result = {
    "schema_version": "raptorq-track-e-multiscenario-capture-v1",
    "bench_filter": BENCH_FILTER,
    "sample_size": 40,
    "warm_up_time_seconds": 0.2,
    "measurement_time_seconds": 0.2,
    "target_root": "/tmp/rch-e5-long-v5",
    "commands": {
        "baseline": "rch exec -- env ASUPERSYNC_GF256_PROFILE_PACK=scalar-conservative-v1 ASUPERSYNC_GF256_DUAL_POLICY=never CARGO_TARGET_DIR=/tmp/rch-e5-long-v5-baseline cargo bench --bench raptorq_benchmark --features simd-intrinsics -- RQ-E-GF256-DUAL --sample-size 40 --warm-up-time 0.2 --measurement-time 0.2",
        "auto": "rch exec -- env ASUPERSYNC_GF256_PROFILE_PACK=auto ASUPERSYNC_GF256_DUAL_POLICY=auto CARGO_TARGET_DIR=/tmp/rch-e5-long-v5-auto cargo bench --bench raptorq_benchmark --features simd-intrinsics -- RQ-E-GF256-DUAL --sample-size 40 --warm-up-time 0.2 --measurement-time 0.2",
        "rollback": "rch exec -- env ASUPERSYNC_GF256_PROFILE_PACK=auto ASUPERSYNC_GF256_DUAL_POLICY=auto ASUPERSYNC_GF256_DUAL_MUL_MIN_TOTAL=32768 ASUPERSYNC_GF256_DUAL_MUL_MAX_TOTAL=32768 CARGO_TARGET_DIR=/tmp/rch-e5-long-v5-rollback cargo bench --bench raptorq_benchmark --features simd-intrinsics -- RQ-E-GF256-DUAL --sample-size 40 --warm-up-time 0.2 --measurement-time 0.2",
    },
    "cases": {
        "baseline": load_case("baseline"),
        "auto": load_case("auto"),
        "rollback": load_case("rollback"),
    },
}

print("JSON_START")
print(json.dumps(result, indent=2, sort_keys=True))
print("JSON_END")
PY
