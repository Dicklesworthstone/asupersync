#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT="${COST_CAPPED_EXPLORATION_ARTIFACT:-${PROJECT_ROOT}/artifacts/cost_capped_exploration_contract_v1.json}"
OUTPUT_ROOT="${COST_CAPPED_EXPLORATION_OUTPUT_ROOT:-${PROJECT_ROOT}/target/cost-capped-exploration-smoke}"
SCENARIO="AA06-SMOKE-GEODESIC-BUDGET"
RUN_ID="${COST_CAPPED_EXPLORATION_RUN_ID:-manual}"
MODE="dry-run"
TIMEOUT_SEC="${COST_CAPPED_EXPLORATION_TIMEOUT_SEC:-900}"
RCH_BIN="${RCH_BIN:-$HOME/.local/bin/rch}"

usage() {
    cat <<'USAGE'
Usage: bash scripts/run_cost_capped_exploration_smoke.sh [options]

Options:
  --list                  List smoke scenarios and exit.
  --dry-run               Emit bundle and run report without executing rch (default).
  --execute               Execute the focused rch-backed smoke proof.
  --scenario <id>         Select scenario id.
  --output-root <path>    Override output root.
  --run-id <id>           Override run id.
  --timeout-sec <sec>     Wall-clock timeout for the rch cargo proof.
USAGE
}

require_jq() {
    if ! command -v jq >/dev/null 2>&1; then
        echo "FATAL: jq is required for cost-capped exploration smoke runner" >&2
        exit 2
    fi
}

require_rch() {
    if ! command -v "$RCH_BIN" >/dev/null 2>&1; then
        echo "FATAL: rch is required and was not found/executable at: ${RCH_BIN}" >&2
        exit 2
    fi
}

test_filter_for_scenario() {
    case "$1" in
        AA06-SMOKE-GEODESIC-BUDGET) printf '%s\n' "geodesic" ;;
        AA06-SMOKE-DPOR-ANALYSIS) printf '%s\n' "dpor" ;;
        AA06-SMOKE-CANONICALIZATION) printf '%s\n' "canonical" ;;
        AA06-SMOKE-FALLBACK-CHAIN) printf '%s\n' "fallback" ;;
        *)
            echo "FATAL: no test filter mapped for scenario $1" >&2
            exit 2
            ;;
    esac
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --list)
            require_jq
            jq -r '.smoke_scenarios[] | "  \(.scenario_id): \(.description)"' "$ARTIFACT"
            exit 0
            ;;
        --dry-run)
            MODE="dry-run"
            shift
            ;;
        --execute)
            MODE="execute"
            shift
            ;;
        --scenario)
            SCENARIO="${2:?missing scenario id}"
            shift 2
            ;;
        --output-root)
            OUTPUT_ROOT="${2:?missing output root}"
            shift 2
            ;;
        --run-id)
            RUN_ID="${2:?missing run id}"
            shift 2
            ;;
        --timeout-sec)
            TIMEOUT_SEC="${2:?missing timeout seconds}"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "FATAL: unknown argument $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

require_jq

DESCRIPTION="$(jq -r --arg scenario "$SCENARIO" '.smoke_scenarios[] | select(.scenario_id == $scenario) | .description' "$ARTIFACT")"
if [[ -z "$DESCRIPTION" || "$DESCRIPTION" == "null" ]]; then
    echo "FATAL: scenario ${SCENARIO} not found in ${ARTIFACT}" >&2
    exit 2
fi

TEST_FILTER="$(test_filter_for_scenario "$SCENARIO")"
RUN_DIR="${OUTPUT_ROOT}/run_${RUN_ID}/${SCENARIO}"
BUNDLE_PATH="${RUN_DIR}/bundle_manifest.json"
RUN_LOG_PATH="${RUN_DIR}/run.log"
RUN_REPORT_PATH="${RUN_DIR}/run_report.json"
mkdir -p "$RUN_DIR"

PROOF_COMMAND=(
    env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 "RUSTFLAGS=-C debuginfo=0" "CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_cost_capped_exploration"
    cargo test -p asupersync --test cost_capped_exploration_contract --features test-internals "$TEST_FILTER" -- --nocapture
)
RCH_COMMAND=("${RCH_BIN}" exec -- "${PROOF_COMMAND[@]}")
RUN_COMMAND=(timeout "$TIMEOUT_SEC" "${RCH_COMMAND[@]}")
printf -v COMMAND '%q ' "${RUN_COMMAND[@]}"
COMMAND="${COMMAND% }"
COMMAND_STATUS=0
REMOTE_TEST_PASSED=false
LOCAL_FALLBACK_DETECTED=false
VALIDATION_PASSED=false
STATUS="dry_run"

jq -n \
    --arg schema "cost-capped-exploration-smoke-bundle-v1" \
    --arg scenario_id "$SCENARIO" \
    --arg description "$DESCRIPTION" \
    --arg run_id "$RUN_ID" \
    --arg mode "$MODE" \
    --arg test_filter "$TEST_FILTER" \
    --arg command "$COMMAND" \
    '{
        schema: $schema,
        scenario_id: $scenario_id,
        description: $description,
        run_id: $run_id,
        mode: $mode,
        test_filter: $test_filter,
        command: $command
    }' >"$BUNDLE_PATH"

{
    printf 'COST_CAPPED_EXPLORATION scenario_id=%s mode=%s test_filter=%s\n' "$SCENARIO" "$MODE" "$TEST_FILTER"
    printf 'COST_CAPPED_EXPLORATION command=%s\n' "$COMMAND"
} >"$RUN_LOG_PATH"

if [[ "$MODE" == "execute" ]]; then
    require_rch
    STATUS="passed"
    set +e
    (
        cd "$PROJECT_ROOT"
        "${RUN_COMMAND[@]}"
    ) >>"$RUN_LOG_PATH" 2>&1
    COMMAND_STATUS=$?
    set -e

    if grep -Eq '^\[RCH\] local \(|falling back to local' "$RUN_LOG_PATH"; then
        COMMAND_STATUS=86
        LOCAL_FALLBACK_DETECTED=true
        echo "FATAL: rch local fallback detected; refusing local cargo execution" >>"$RUN_LOG_PATH"
    fi

    if grep -q 'test result: ok' "$RUN_LOG_PATH"; then
        REMOTE_TEST_PASSED=true
    fi

    if [[ "$COMMAND_STATUS" -ne 0 || "$LOCAL_FALLBACK_DETECTED" == "true" || "$REMOTE_TEST_PASSED" != "true" ]]; then
        STATUS="failed"
    else
        VALIDATION_PASSED=true
    fi
else
    VALIDATION_PASSED=true
fi

jq -n \
    --arg schema "cost-capped-exploration-smoke-run-report-v1" \
    --arg scenario_id "$SCENARIO" \
    --arg run_id "$RUN_ID" \
    --arg mode "$MODE" \
    --arg status "$STATUS" \
    --arg command "$COMMAND" \
    --arg command_status "$COMMAND_STATUS" \
    --arg remote_test_passed "$REMOTE_TEST_PASSED" \
    --arg local_fallback_detected "$LOCAL_FALLBACK_DETECTED" \
    --arg validation_passed "$VALIDATION_PASSED" \
    --arg test_filter "$TEST_FILTER" \
    --arg bundle_path "$BUNDLE_PATH" \
    --arg run_log_path "$RUN_LOG_PATH" \
    '{
        schema: $schema,
        scenario_id: $scenario_id,
        run_id: $run_id,
        mode: $mode,
        status: $status,
        command: $command,
        command_status: ($command_status | tonumber),
        remote_test_passed: ($remote_test_passed == "true"),
        local_fallback_detected: ($local_fallback_detected == "true"),
        validation_passed: ($validation_passed == "true"),
        test_filter: $test_filter,
        bundle_path: $bundle_path,
        run_log_path: $run_log_path
    }' >"$RUN_REPORT_PATH"

printf 'COST_CAPPED_EXPLORATION_RUN scenario_id=%s status=%s run_report=%s\n' \
    "$SCENARIO" "$STATUS" "$RUN_REPORT_PATH"

if [[ "$VALIDATION_PASSED" != "true" ]]; then
    tail -20 "$RUN_LOG_PATH"
    if [[ "$COMMAND_STATUS" -eq 0 ]]; then
        exit 1
    fi
    exit "$COMMAND_STATUS"
fi
