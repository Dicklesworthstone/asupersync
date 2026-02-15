#!/usr/bin/env bash
set -euo pipefail

# Deterministic RaptorQ E2E Scenario Runner (asupersync-wdk6c / D6)
#
# Runs deterministic happy/boundary/failure scenario filters from
# tests/raptorq_conformance.rs with profile-aware selection and
# machine-parseable artifacts.
#
# Usage:
#   ./scripts/run_raptorq_e2e.sh --list
#   ./scripts/run_raptorq_e2e.sh --profile fast
#   ./scripts/run_raptorq_e2e.sh --profile full
#   ./scripts/run_raptorq_e2e.sh --profile forensics
#   ./scripts/run_raptorq_e2e.sh --profile full --scenario RQ-E2E-FAILURE-INSUFFICIENT
#
# Environment:
#   RCH_BIN        - remote compilation helper executable (default: rch)
#   E2E_TIMEOUT    - per-scenario timeout seconds (default: 600)
#   TEST_THREADS   - cargo test thread count (default: 1)
#   NO_PREFLIGHT   - set to 1 to skip cargo --no-run preflight

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
RCH_BIN="${RCH_BIN:-rch}"
E2E_TIMEOUT="${E2E_TIMEOUT:-600}"
TEST_THREADS="${TEST_THREADS:-1}"
PROFILE="fast"
SCENARIO_FILTER=""
LIST_ONLY=0

declare -a SCENARIO_IDS=(
    "RQ-E2E-HAPPY-NO-LOSS"
    "RQ-E2E-HAPPY-RANDOM-LOSS"
    "RQ-E2E-HAPPY-REPAIR-ONLY"
    "RQ-E2E-BOUNDARY-K1"
    "RQ-E2E-BOUNDARY-TINY-SYMBOL"
    "RQ-E2E-BOUNDARY-LARGE-SYMBOL"
    "RQ-E2E-FAILURE-INSUFFICIENT"
    "RQ-E2E-FAILURE-SIZE-MISMATCH"
    "RQ-E2E-REPORT-DETERMINISM"
)

declare -A SCENARIO_TEST_FILTER=(
    ["RQ-E2E-HAPPY-NO-LOSS"]="roundtrip_no_loss"
    ["RQ-E2E-HAPPY-RANDOM-LOSS"]="roundtrip_with_source_loss"
    ["RQ-E2E-HAPPY-REPAIR-ONLY"]="roundtrip_repair_only"
    ["RQ-E2E-BOUNDARY-K1"]="edge_case_k_equals_1"
    ["RQ-E2E-BOUNDARY-TINY-SYMBOL"]="edge_case_tiny_symbol_size"
    ["RQ-E2E-BOUNDARY-LARGE-SYMBOL"]="edge_case_large_symbol_size"
    ["RQ-E2E-FAILURE-INSUFFICIENT"]="insufficient_symbols_fails"
    ["RQ-E2E-FAILURE-SIZE-MISMATCH"]="symbol_size_mismatch_fails"
    ["RQ-E2E-REPORT-DETERMINISM"]="e2e_pipeline_reports_are_deterministic"
)

declare -A SCENARIO_CATEGORY=(
    ["RQ-E2E-HAPPY-NO-LOSS"]="happy"
    ["RQ-E2E-HAPPY-RANDOM-LOSS"]="happy"
    ["RQ-E2E-HAPPY-REPAIR-ONLY"]="happy"
    ["RQ-E2E-BOUNDARY-K1"]="boundary"
    ["RQ-E2E-BOUNDARY-TINY-SYMBOL"]="boundary"
    ["RQ-E2E-BOUNDARY-LARGE-SYMBOL"]="boundary"
    ["RQ-E2E-FAILURE-INSUFFICIENT"]="failure"
    ["RQ-E2E-FAILURE-SIZE-MISMATCH"]="failure"
    ["RQ-E2E-REPORT-DETERMINISM"]="composite"
)

declare -A SCENARIO_REPLAY_REF=(
    ["RQ-E2E-HAPPY-NO-LOSS"]="replay:rq-u-happy-source-heavy-v1"
    ["RQ-E2E-HAPPY-RANDOM-LOSS"]="replay:rq-e2e-typical-random-loss-v1"
    ["RQ-E2E-HAPPY-REPAIR-ONLY"]="replay:rq-u-happy-repair-only-v1"
    ["RQ-E2E-BOUNDARY-K1"]="replay:rq-u-boundary-tiny-k1-v1"
    ["RQ-E2E-BOUNDARY-TINY-SYMBOL"]="replay:rq-u-boundary-tiny-symbol-v1"
    ["RQ-E2E-BOUNDARY-LARGE-SYMBOL"]="replay:rq-u-boundary-large-symbol-v1"
    ["RQ-E2E-FAILURE-INSUFFICIENT"]="replay:rq-u-error-insufficient-v1"
    ["RQ-E2E-FAILURE-SIZE-MISMATCH"]="replay:rq-u-error-size-mismatch-v1"
    ["RQ-E2E-REPORT-DETERMINISM"]="replay:rq-e2e-systematic-only-v1"
)

declare -A SCENARIO_REPLAY_EXTRA=(
    ["RQ-E2E-HAPPY-NO-LOSS"]=""
    ["RQ-E2E-HAPPY-RANDOM-LOSS"]=""
    ["RQ-E2E-HAPPY-REPAIR-ONLY"]=""
    ["RQ-E2E-BOUNDARY-K1"]=""
    ["RQ-E2E-BOUNDARY-TINY-SYMBOL"]=""
    ["RQ-E2E-BOUNDARY-LARGE-SYMBOL"]=""
    ["RQ-E2E-FAILURE-INSUFFICIENT"]=""
    ["RQ-E2E-FAILURE-SIZE-MISMATCH"]=""
    ["RQ-E2E-REPORT-DETERMINISM"]="replay:rq-e2e-typical-random-loss-v1,replay:rq-e2e-burst-loss-late-v1,replay:rq-e2e-insufficient-symbols-v1"
)

declare -A SCENARIO_UNIT_SENTINEL=(
    ["RQ-E2E-HAPPY-NO-LOSS"]="src/raptorq/tests.rs::repair_zero_only_source"
    ["RQ-E2E-HAPPY-RANDOM-LOSS"]="tests/raptorq_perf_invariants.rs::cross_parameter_roundtrip_sweep"
    ["RQ-E2E-HAPPY-REPAIR-ONLY"]="src/raptorq/tests.rs::all_repair_no_source"
    ["RQ-E2E-BOUNDARY-K1"]="src/raptorq/tests.rs::tiny_block_k1"
    ["RQ-E2E-BOUNDARY-TINY-SYMBOL"]="src/raptorq/tests.rs::tiny_symbol_size"
    ["RQ-E2E-BOUNDARY-LARGE-SYMBOL"]="src/raptorq/tests.rs::large_symbol_size"
    ["RQ-E2E-FAILURE-INSUFFICIENT"]="src/raptorq/tests.rs::insufficient_symbols_error"
    ["RQ-E2E-FAILURE-SIZE-MISMATCH"]="src/raptorq/tests.rs::symbol_size_mismatch_error"
    ["RQ-E2E-REPORT-DETERMINISM"]="tests/raptorq_conformance.rs::e2e_pipeline_reports_are_deterministic"
)

declare -A SCENARIO_PROFILES=(
    ["RQ-E2E-HAPPY-NO-LOSS"]="fast,full"
    ["RQ-E2E-HAPPY-RANDOM-LOSS"]="full,forensics"
    ["RQ-E2E-HAPPY-REPAIR-ONLY"]="full,forensics"
    ["RQ-E2E-BOUNDARY-K1"]="fast,full"
    ["RQ-E2E-BOUNDARY-TINY-SYMBOL"]="fast,full"
    ["RQ-E2E-BOUNDARY-LARGE-SYMBOL"]="full,forensics"
    ["RQ-E2E-FAILURE-INSUFFICIENT"]="fast,full,forensics"
    ["RQ-E2E-FAILURE-SIZE-MISMATCH"]="full,forensics"
    ["RQ-E2E-REPORT-DETERMINISM"]="fast,full,forensics"
)

usage() {
    cat <<'USAGE'
Usage: ./scripts/run_raptorq_e2e.sh [options]

Options:
  --profile <fast|full|forensics>   Scenario profile (default: fast)
  --scenario <SCENARIO_ID>          Run one scenario regardless of profile
  --list                            List available scenarios and exit
  -h, --help                        Show this help
USAGE
}

has_scenario() {
    local candidate="$1"
    local id
    for id in "${SCENARIO_IDS[@]}"; do
        if [[ "$id" == "$candidate" ]]; then
            return 0
        fi
    done
    return 1
}

matches_profile() {
    local scenario_id="$1"
    local profile="$2"
    local profiles_csv="${SCENARIO_PROFILES[$scenario_id]}"
    case ",${profiles_csv}," in
        *",${profile},"*) return 0 ;;
        *) return 1 ;;
    esac
}

json_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

selected_for_run() {
    local scenario_id="$1"
    if [[ -n "$SCENARIO_FILTER" ]]; then
        [[ "$scenario_id" == "$SCENARIO_FILTER" ]]
        return
    fi
    matches_profile "$scenario_id" "$PROFILE"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --profile)
            PROFILE="${2:-}"
            shift 2
            ;;
        --scenario)
            SCENARIO_FILTER="${2:-}"
            shift 2
            ;;
        --list)
            LIST_ONLY=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

if [[ "$PROFILE" != "fast" && "$PROFILE" != "full" && "$PROFILE" != "forensics" ]]; then
    echo "Invalid profile: $PROFILE" >&2
    exit 1
fi

if [[ -n "$SCENARIO_FILTER" ]] && ! has_scenario "$SCENARIO_FILTER"; then
    echo "Unknown scenario: $SCENARIO_FILTER" >&2
    exit 1
fi

if [[ "$LIST_ONLY" -eq 1 ]]; then
    echo "Available deterministic RaptorQ E2E scenarios:"
    for scenario_id in "${SCENARIO_IDS[@]}"; do
        printf "  %-34s category=%-9s profiles=%-18s test=%s\n" \
            "$scenario_id" \
            "${SCENARIO_CATEGORY[$scenario_id]}" \
            "${SCENARIO_PROFILES[$scenario_id]}" \
            "${SCENARIO_TEST_FILTER[$scenario_id]}"
    done
    exit 0
fi

if ! command -v "$RCH_BIN" >/dev/null 2>&1; then
    echo "Required executable not found: $RCH_BIN" >&2
    exit 1
fi

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RUN_DIR="${PROJECT_ROOT}/target/e2e-results/raptorq/${PROFILE}_${TIMESTAMP}"
SCENARIO_LOG="${RUN_DIR}/scenarios.ndjson"
SUMMARY_FILE="${RUN_DIR}/summary.json"
PREFLIGHT_LOG="${RUN_DIR}/preflight.log"

mkdir -p "$RUN_DIR"
: > "$SCENARIO_LOG"

echo "==================================================================="
echo "        RaptorQ Deterministic E2E Scenario Suite (D6)             "
echo "==================================================================="
echo "Profile:         ${PROFILE}"
if [[ -n "$SCENARIO_FILTER" ]]; then
    echo "Scenario filter: ${SCENARIO_FILTER}"
fi
echo "Timeout:         ${E2E_TIMEOUT}s per scenario"
echo "Artifact dir:    ${RUN_DIR}"
echo "Scenario log:    ${SCENARIO_LOG}"
echo ""

if [[ "${NO_PREFLIGHT:-0}" != "1" ]]; then
    echo ">>> [preflight] compile check via rch..."
    if ! "$RCH_BIN" exec -- cargo test --test raptorq_conformance --no-run >"$PREFLIGHT_LOG" 2>&1; then
        echo "Preflight compilation failed. See ${PREFLIGHT_LOG}" >&2
        cat > "$SUMMARY_FILE" <<EOF
{
  "schema_version": "raptorq-e2e-suite-log-v1",
  "profile": "$(json_escape "$PROFILE")",
  "status": "preflight_failed",
  "artifact_dir": "$(json_escape "$RUN_DIR")",
  "preflight_log": "$(json_escape "$PREFLIGHT_LOG")",
  "repro_cmd": "rch exec -- cargo test --test raptorq_conformance --no-run"
}
EOF
        exit 1
    fi
fi

selected_count=0
passed_count=0
failed_count=0

for scenario_id in "${SCENARIO_IDS[@]}"; do
    if ! selected_for_run "$scenario_id"; then
        continue
    fi

    selected_count=$((selected_count + 1))

    test_filter="${SCENARIO_TEST_FILTER[$scenario_id]}"
    category="${SCENARIO_CATEGORY[$scenario_id]}"
    replay_ref="${SCENARIO_REPLAY_REF[$scenario_id]}"
    replay_extra="${SCENARIO_REPLAY_EXTRA[$scenario_id]}"
    unit_sentinel="${SCENARIO_UNIT_SENTINEL[$scenario_id]}"
    scenario_profiles="${SCENARIO_PROFILES[$scenario_id]}"
    scenario_log_file="${RUN_DIR}/${scenario_id}.log"
    repro_cmd="rch exec -- cargo test --test raptorq_conformance ${test_filter} -- --nocapture --test-threads=${TEST_THREADS}"

    echo ">>> [${selected_count}] ${scenario_id} (${category})"
    start_s="$(date +%s)"

    set +e
    timeout "$E2E_TIMEOUT" "$RCH_BIN" exec -- cargo test --test raptorq_conformance "$test_filter" -- --nocapture --test-threads="$TEST_THREADS" >"$scenario_log_file" 2>&1
    rc=$?
    set -e

    end_s="$(date +%s)"
    duration_ms=$(((end_s - start_s) * 1000))
    tests_passed="$(grep -c "^test .* ok$" "$scenario_log_file" 2>/dev/null || true)"
    tests_failed="$(grep -c "^test .* FAILED$" "$scenario_log_file" 2>/dev/null || true)"

    status="pass"
    if [[ "$rc" -ne 0 ]]; then
        status="fail"
        failed_count=$((failed_count + 1))
        if [[ "$rc" -eq 124 ]]; then
            echo "    FAIL (timeout) -> ${scenario_log_file}"
        else
            echo "    FAIL (exit ${rc}) -> ${scenario_log_file}"
        fi
        echo "    repro: ${repro_cmd}"
    else
        passed_count=$((passed_count + 1))
        echo "    PASS (${tests_passed} tests)"
    fi

    printf '{"schema_version":"raptorq-e2e-scenario-log-v1","scenario_id":"%s","category":"%s","profile":"%s","profile_set":"%s","test_filter":"%s","replay_ref":"%s","replay_ref_extra":"%s","unit_sentinel":"%s","status":"%s","exit_code":%d,"duration_ms":%d,"tests_passed":%d,"tests_failed":%d,"log_path":"%s","repro_cmd":"%s"}\n' \
        "$(json_escape "$scenario_id")" \
        "$(json_escape "$category")" \
        "$(json_escape "$PROFILE")" \
        "$(json_escape "$scenario_profiles")" \
        "$(json_escape "$test_filter")" \
        "$(json_escape "$replay_ref")" \
        "$(json_escape "$replay_extra")" \
        "$(json_escape "$unit_sentinel")" \
        "$(json_escape "$status")" \
        "$rc" \
        "$duration_ms" \
        "$tests_passed" \
        "$tests_failed" \
        "$(json_escape "$scenario_log_file")" \
        "$(json_escape "$repro_cmd")" \
        >> "$SCENARIO_LOG"
done

if [[ "$selected_count" -eq 0 ]]; then
    echo "No scenarios selected for profile=${PROFILE} filter=${SCENARIO_FILTER:-<none>}" >&2
    exit 2
fi

suite_status="pass"
if [[ "$failed_count" -gt 0 ]]; then
    suite_status="fail"
fi

cat > "$SUMMARY_FILE" <<EOF
{
  "schema_version": "raptorq-e2e-suite-log-v1",
  "suite_id": "RQ-E2E-SUITE-D6",
  "profile": "$(json_escape "$PROFILE")",
  "selected_scenarios": ${selected_count},
  "passed_scenarios": ${passed_count},
  "failed_scenarios": ${failed_count},
  "status": "$(json_escape "$suite_status")",
  "artifact_dir": "$(json_escape "$RUN_DIR")",
  "scenario_log": "$(json_escape "$SCENARIO_LOG")",
  "preflight_log": "$(json_escape "$PREFLIGHT_LOG")"
}
EOF

echo ""
echo "==================================================================="
echo "                RaptorQ Deterministic E2E Summary                 "
echo "==================================================================="
echo "Scenarios:  ${selected_count}"
echo "Passed:     ${passed_count}"
echo "Failed:     ${failed_count}"
echo "Status:     ${suite_status}"
echo "Summary:    ${SUMMARY_FILE}"
echo "Scenarios:  ${SCENARIO_LOG}"
echo "==================================================================="

if [[ "$failed_count" -gt 0 ]]; then
    exit 1
fi

