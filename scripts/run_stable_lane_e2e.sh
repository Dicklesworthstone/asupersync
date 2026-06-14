#!/usr/bin/env bash
# Stable Rust lane E2E runner (br-asupersync-stable-rust-track-tq3ajf.2).
#
# All Cargo stages are executed through RCH. The lane intentionally uses an
# audited stable feature subset: default features are disabled so the
# default-on nightly-outcome-try gate is not selected.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
GENERATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
RUN_ID="${STABLE_RUST_LANE_RUN_ID:-${TIMESTAMP}}"
OUTPUT_ROOT="${STABLE_RUST_LANE_OUTPUT_ROOT:-${PROJECT_ROOT}/target/e2e-results/stable_rust_lane_e2e}"
OUTPUT_DIR="${OUTPUT_ROOT}/${RUN_ID}"
EVENTS_NDJSON="${OUTPUT_DIR}/events.ndjson"
SUMMARY_JSON="${OUTPUT_DIR}/summary.json"
RCH_BIN="${RCH_BIN:-rch}"
RCH_REQUIRE_REMOTE="${RCH_REQUIRE_REMOTE:-1}"
STABLE_TARGET_DIR="${STABLE_RUST_CARGO_TARGET_DIR:-${TMPDIR:-/tmp}/rch_target_asupersync_stable_lane}"
RUSTFLAGS_VALUE="${STABLE_RUST_RUSTFLAGS:--C debuginfo=0}"

STAGE_IDS=(
    "stable-check"
    "stable-clippy"
    "stable-outcome-unit"
)

STAGE_DESCRIPTIONS=(
    "cargo +stable check on the audited stable feature subset"
    "cargo +stable clippy on the audited stable feature subset"
    "cargo +stable test for Outcome semantics on the audited stable feature subset"
)

usage() {
    cat <<'USAGE'
Usage:
  scripts/run_stable_lane_e2e.sh
  scripts/run_stable_lane_e2e.sh --list-stages

Environment:
  STABLE_RUST_LANE_RUN_ID       Stable run id used under target/e2e-results.
  STABLE_RUST_LANE_OUTPUT_ROOT  Output root for summary.json and events.ndjson.
  STABLE_RUST_CARGO_TARGET_DIR  Shared Cargo target dir for the RCH worker.
  RCH_BIN                       RCH executable, default: rch.
  RCH_REQUIRE_REMOTE            Remote-only RCH policy, default: 1.
USAGE
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    usage
    exit 0
fi

if [[ "${1:-}" == "--list-stages" ]]; then
    for index in "${!STAGE_IDS[@]}"; do
        printf '%s\t%s\n' "${STAGE_IDS[$index]}" "${STAGE_DESCRIPTIONS[$index]}"
    done
    exit 0
fi

if [[ "$#" -gt 0 ]]; then
    echo "Unknown argument: $1" >&2
    usage >&2
    exit 2
fi

json_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

utc_now() {
    date -u +%Y-%m-%dT%H:%M:%SZ
}

command_string() {
    local rendered=""
    local part
    for part in "$@"; do
        if [[ -n "$rendered" ]]; then
            rendered+=" "
        fi
        rendered+="$(printf '%q' "$part")"
    done
    printf '%s' "$rendered"
}

emit_event() {
    local stage_id="$1"
    local event="$2"
    local status="$3"
    local exit_code="$4"
    local log_file="$5"
    local command="$6"
    local emitted_at
    emitted_at="$(utc_now)"
    printf '{"schema_version":"stable-rust-lane-event-v1","run_id":"%s","stage_id":"%s","event":"%s","status":"%s","exit_code":%s,"emitted_at":"%s","log_file":"%s","command":"%s"}\n' \
        "$(json_escape "$RUN_ID")" \
        "$(json_escape "$stage_id")" \
        "$(json_escape "$event")" \
        "$(json_escape "$status")" \
        "$exit_code" \
        "$(json_escape "$emitted_at")" \
        "$(json_escape "$log_file")" \
        "$(json_escape "$command")" \
        >> "$EVENTS_NDJSON"
}

run_stage() {
    local stage_id="$1"
    local description="$2"
    shift 2

    local log_file="${OUTPUT_DIR}/${stage_id}.log"
    local -a cargo_cmd=("$@")
    local -a cmd=(
        env
        "RCH_REQUIRE_REMOTE=${RCH_REQUIRE_REMOTE}"
        "$RCH_BIN"
        exec
        --
        env
        "CARGO_TARGET_DIR=${STABLE_TARGET_DIR}"
        "CARGO_INCREMENTAL=0"
        "CARGO_PROFILE_TEST_DEBUG=0"
        "RUSTFLAGS=${RUSTFLAGS_VALUE}"
        "${cargo_cmd[@]}"
    )
    local rendered
    rendered="$(command_string "${cmd[@]}")"

    echo "stable lane stage: ${stage_id} - ${description}"
    echo "command: ${rendered}" > "$log_file"
    emit_event "$stage_id" "start" "running" 0 "$log_file" "$rendered"

    set +e
    "${cmd[@]}" >> "$log_file" 2>&1
    local rc=$?
    set -e

    if [[ "$rc" -eq 0 ]]; then
        emit_event "$stage_id" "finish" "passed" "$rc" "$log_file" "$rendered"
    else
        emit_event "$stage_id" "finish" "failed" "$rc" "$log_file" "$rendered"
    fi
    return "$rc"
}

mkdir -p "$OUTPUT_DIR"
: > "$EVENTS_NDJSON"

overall_status="passed"
failed_stage=""

if ! run_stage \
    "${STAGE_IDS[0]}" \
    "${STAGE_DESCRIPTIONS[0]}" \
    cargo +stable check -p asupersync --no-default-features --features proc-macros; then
    overall_status="failed"
    failed_stage="${STAGE_IDS[0]}"
fi

if [[ "$overall_status" == "passed" ]]; then
    if ! run_stage \
        "${STAGE_IDS[1]}" \
        "${STAGE_DESCRIPTIONS[1]}" \
        cargo +stable clippy -p asupersync --no-default-features --features proc-macros -- -D warnings; then
        overall_status="failed"
        failed_stage="${STAGE_IDS[1]}"
    fi
fi

if [[ "$overall_status" == "passed" ]]; then
    if ! run_stage \
        "${STAGE_IDS[2]}" \
        "${STAGE_DESCRIPTIONS[2]}" \
        cargo +stable test -p asupersync --lib --no-default-features --features proc-macros types::outcome; then
        overall_status="failed"
        failed_stage="${STAGE_IDS[2]}"
    fi
fi

ended_at="$(utc_now)"

cat > "$SUMMARY_JSON" <<EOF_SUMMARY
{
  "schema_version": "e2e-suite-summary-v3",
  "suite_id": "stable_rust_lane_e2e",
  "scenario_id": "E2E-SUITE-STABLE-RUST-LANE",
  "seed": "stable-rust-lane-v1",
  "started_ts": "${GENERATED_AT}",
  "ended_ts": "${ended_at}",
  "status": "${overall_status}",
  "repro_command": "bash scripts/run_stable_lane_e2e.sh",
  "artifact_path": "${OUTPUT_DIR}",
  "run_id": "${RUN_ID}",
  "target_dir": "${STABLE_TARGET_DIR}",
  "toolchain": "stable",
  "feature_subset": "--no-default-features --features proc-macros",
  "failed_stage": "${failed_stage}",
  "events_ndjson": "${EVENTS_NDJSON}"
}
EOF_SUMMARY

echo "Summary: ${SUMMARY_JSON}"
echo "Artifacts: ${OUTPUT_DIR}"

if [[ "$overall_status" == "passed" ]]; then
    exit 0
fi
exit 1
