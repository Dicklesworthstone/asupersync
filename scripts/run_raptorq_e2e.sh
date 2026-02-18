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

declare -A SCENARIO_ASSERTION_ID=(
    ["RQ-E2E-HAPPY-NO-LOSS"]="E2E-ROUNDTRIP-NO-LOSS"
    ["RQ-E2E-HAPPY-RANDOM-LOSS"]="E2E-ROUNDTRIP-RANDOM-LOSS"
    ["RQ-E2E-HAPPY-REPAIR-ONLY"]="E2E-ROUNDTRIP-REPAIR-ONLY"
    ["RQ-E2E-BOUNDARY-K1"]="E2E-BOUNDARY-K1"
    ["RQ-E2E-BOUNDARY-TINY-SYMBOL"]="E2E-BOUNDARY-TINY-SYMBOL"
    ["RQ-E2E-BOUNDARY-LARGE-SYMBOL"]="E2E-BOUNDARY-LARGE-SYMBOL"
    ["RQ-E2E-FAILURE-INSUFFICIENT"]="E2E-ERROR-INSUFFICIENT"
    ["RQ-E2E-FAILURE-SIZE-MISMATCH"]="E2E-ERROR-SIZE-MISMATCH"
    ["RQ-E2E-REPORT-DETERMINISM"]="E2E-REPORT-DETERMINISM"
)

declare -A SCENARIO_SEED=(
    ["RQ-E2E-HAPPY-NO-LOSS"]="42"
    ["RQ-E2E-HAPPY-RANDOM-LOSS"]="123"
    ["RQ-E2E-HAPPY-REPAIR-ONLY"]="456"
    ["RQ-E2E-BOUNDARY-K1"]="42"
    ["RQ-E2E-BOUNDARY-TINY-SYMBOL"]="200"
    ["RQ-E2E-BOUNDARY-LARGE-SYMBOL"]="300"
    ["RQ-E2E-FAILURE-INSUFFICIENT"]="500"
    ["RQ-E2E-FAILURE-SIZE-MISMATCH"]="600"
    ["RQ-E2E-REPORT-DETERMINISM"]="42"
)

declare -A SCENARIO_PARAMETER_SET=(
    ["RQ-E2E-HAPPY-NO-LOSS"]="k=8,symbol_size=64,loss=none"
    ["RQ-E2E-HAPPY-RANDOM-LOSS"]="k=10,symbol_size=32,loss=random"
    ["RQ-E2E-HAPPY-REPAIR-ONLY"]="k=6,symbol_size=24,loss=repair_only"
    ["RQ-E2E-BOUNDARY-K1"]="k=1,symbol_size=16,loss=none"
    ["RQ-E2E-BOUNDARY-TINY-SYMBOL"]="k=4,symbol_size=1,loss=none"
    ["RQ-E2E-BOUNDARY-LARGE-SYMBOL"]="k=4,symbol_size=4096,loss=none"
    ["RQ-E2E-FAILURE-INSUFFICIENT"]="k=8,symbol_size=32,loss=insufficient"
    ["RQ-E2E-FAILURE-SIZE-MISMATCH"]="k=4,symbol_size=32,loss=symbol_size_mismatch"
    ["RQ-E2E-REPORT-DETERMINISM"]="k=16,symbol_size=64,loss=deterministic_matrix"
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

validate_scenario_contract() {
    local scenario_json="$1"
    jq -e '
        .schema_version == "raptorq-e2e-scenario-log-v2" and
        (.scenario_id | type == "string" and length > 0) and
        (.category | type == "string" and length > 0) and
        (.profile | type == "string" and (. == "fast" or . == "full" or . == "forensics")) and
        (.profile_set | type == "string" and length > 0) and
        (.test_filter | type == "string" and length > 0) and
        (.replay_ref | type == "string" and length > 0) and
        (.unit_sentinel | type == "string" and length > 0) and
        (.assertion_id | type == "string" and length > 0) and
        (.run_id | type == "string" and length > 0) and
        (.parameter_set | type == "string" and length > 0) and
        (.artifact_path | type == "string" and length > 0) and
        (.log_path | type == "string" and length > 0) and
        (.artifact_path == .log_path) and
        (.repro_command | type == "string" and test("^((rch exec -- )?cargo test --test raptorq_conformance )")) and
        (.phase_markers == ["encode","loss","decode","proof","report"]) and
        (.status == "pass" or .status == "fail") and
        (.seed | type == "number" and . >= 0 and floor == .) and
        (.exit_code | type == "number" and floor == .) and
        (.duration_ms | type == "number" and . >= 0 and floor == .) and
        (.tests_passed | type == "number" and . >= 0 and floor == .) and
        (.tests_failed | type == "number" and . >= 0 and floor == .)
    ' <<<"$scenario_json" >/dev/null
}

print_scenario_contract_help() {
    cat >&2 <<'EOF'
Forensic log contract violation (D3 gate).
Required scenario fields:
  - schema_version=raptorq-e2e-scenario-log-v2
  - non-empty: scenario_id, category, profile, profile_set, test_filter, replay_ref,
    unit_sentinel, assertion_id, run_id, parameter_set, artifact_path, log_path, repro_command
  - phase_markers exactly: ["encode","loss","decode","proof","report"]
  - status in {pass, fail}; integer seed/exit_code/duration_ms/tests_passed/tests_failed
  - repro_command starts with "cargo test --test raptorq_conformance ..." (optionally prefixed by "rch exec -- ")
Remediation:
  1. Update scenario JSON formatter in scripts/run_raptorq_e2e.sh.
  2. Keep schema version and marker order stable unless intentionally version-bumped.
  3. Re-run with: ./scripts/run_raptorq_e2e.sh --profile forensics --scenario RQ-E2E-FAILURE-INSUFFICIENT
EOF
}

validate_suite_contract() {
    local summary_file="$1"
    local scenario_log="$2"
    local expected_count
    local actual_count

    jq -e '
        .schema_version == "raptorq-e2e-suite-log-v1" and
        .suite_id == "RQ-E2E-SUITE-D6" and
        (.profile | type == "string" and (. == "fast" or . == "full" or . == "forensics")) and
        (.selected_scenarios | type == "number" and . >= 1 and floor == .) and
        (.passed_scenarios | type == "number" and . >= 0 and floor == .) and
        (.failed_scenarios | type == "number" and . >= 0 and floor == .) and
        (.status == "pass" or .status == "fail") and
        (.artifact_dir | type == "string" and length > 0) and
        (.scenario_log | type == "string" and length > 0) and
        (.preflight_log | type == "string" and length > 0) and
        ((.passed_scenarios + .failed_scenarios) == .selected_scenarios) and
        ((.status == "pass" and .failed_scenarios == 0) or (.status == "fail" and .failed_scenarios >= 1))
    ' "$summary_file" >/dev/null || return 1

    expected_count="$(jq -r '.selected_scenarios' "$summary_file" 2>/dev/null || true)"
    actual_count="$(jq -s 'length' "$scenario_log" 2>/dev/null || true)"
    if [[ -z "$expected_count" || -z "$actual_count" || "$expected_count" != "$actual_count" ]]; then
        return 1
    fi

    jq -s -e '
        length > 0 and all(.[]; 
            .schema_version == "raptorq-e2e-scenario-log-v2" and
            (.scenario_id | type == "string" and length > 0) and
            (.profile | type == "string" and (. == "fast" or . == "full" or . == "forensics")) and
            (.status == "pass" or .status == "fail") and
            (.artifact_path | type == "string" and length > 0) and
            (.log_path | type == "string" and length > 0) and
            (.repro_command | type == "string" and test("^((rch exec -- )?cargo test --test raptorq_conformance )"))
        )
    ' "$scenario_log" >/dev/null
}

print_suite_contract_help() {
    cat >&2 <<'EOF'
Suite forensic contract violation (D3 gate).
Required suite fields:
  - schema_version=raptorq-e2e-suite-log-v1, suite_id=RQ-E2E-SUITE-D6
  - valid profile marker (fast/full/forensics)
  - selected_scenarios == passed_scenarios + failed_scenarios
  - selected_scenarios must equal number of NDJSON scenario records
  - status=pass only when failed_scenarios=0
Remediation:
  1. Verify summary writer in scripts/run_raptorq_e2e.sh.
  2. Ensure every selected scenario appends exactly one NDJSON record.
  3. Re-run deterministic gate and inspect generated summary/scenarios files.
EOF
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

if ! command -v jq >/dev/null 2>&1; then
    echo "Required executable not found: jq" >&2
    exit 1
fi

RUN_WITH_RCH=1
if ! command -v "$RCH_BIN" >/dev/null 2>&1; then
    RUN_WITH_RCH=0
    echo "warning: '$RCH_BIN' not found; falling back to local cargo execution for this run" >&2
fi

REPRO_PREFIX="rch exec -- "
if [[ "$RUN_WITH_RCH" -eq 0 ]]; then
    REPRO_PREFIX=""
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
    echo ">>> [preflight] compile check..."
    set +e
    if [[ "$RUN_WITH_RCH" -eq 1 ]]; then
        "$RCH_BIN" exec -- cargo test --test raptorq_conformance --no-run >"$PREFLIGHT_LOG" 2>&1
    else
        cargo test --test raptorq_conformance --no-run >"$PREFLIGHT_LOG" 2>&1
    fi
    preflight_rc="$?"
    set -e
    if [[ "$preflight_rc" -ne 0 ]]; then
        echo "Preflight compilation failed. See ${PREFLIGHT_LOG}" >&2
        cat > "$SUMMARY_FILE" <<EOF
{
  "schema_version": "raptorq-e2e-suite-log-v1",
  "profile": "$(json_escape "$PROFILE")",
  "status": "preflight_failed",
  "artifact_dir": "$(json_escape "$RUN_DIR")",
  "preflight_log": "$(json_escape "$PREFLIGHT_LOG")",
  "repro_command": "$(json_escape "${REPRO_PREFIX}cargo test --test raptorq_conformance --no-run")"
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
    assertion_id="${SCENARIO_ASSERTION_ID[$scenario_id]}"
    scenario_seed="${SCENARIO_SEED[$scenario_id]}"
    parameter_set="${SCENARIO_PARAMETER_SET[$scenario_id]}"
    scenario_profiles="${SCENARIO_PROFILES[$scenario_id]}"
    scenario_log_file="${RUN_DIR}/${scenario_id}.log"
    run_id="${scenario_id}-${PROFILE}"
    repro_cmd="${REPRO_PREFIX}cargo test --test raptorq_conformance ${test_filter} -- --nocapture --test-threads=${TEST_THREADS}"

    echo ">>> [${selected_count}] ${scenario_id} (${category})"
    start_s="$(date +%s)"

    set +e
    if [[ "$RUN_WITH_RCH" -eq 1 ]]; then
        timeout "$E2E_TIMEOUT" "$RCH_BIN" exec -- cargo test --test raptorq_conformance "$test_filter" -- --nocapture --test-threads="$TEST_THREADS" >"$scenario_log_file" 2>&1
    else
        timeout "$E2E_TIMEOUT" cargo test --test raptorq_conformance "$test_filter" -- --nocapture --test-threads="$TEST_THREADS" >"$scenario_log_file" 2>&1
    fi
    rc=$?
    set -e

    end_s="$(date +%s)"
    duration_ms=$(((end_s - start_s) * 1000))
    tests_passed="$(grep -c "^test .* ok$" "$scenario_log_file" 2>/dev/null || true)"
    tests_failed="$(grep -c "^test .* FAILED$" "$scenario_log_file" 2>/dev/null || true)"

    status="pass"
    contract_failure=0
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

    printf -v scenario_json '{"schema_version":"raptorq-e2e-scenario-log-v2","scenario_id":"%s","category":"%s","profile":"%s","profile_set":"%s","test_filter":"%s","replay_ref":"%s","replay_ref_extra":"%s","unit_sentinel":"%s","assertion_id":"%s","run_id":"%s","seed":%s,"parameter_set":"%s","phase_markers":["encode","loss","decode","proof","report"],"status":"%s","exit_code":%d,"duration_ms":%d,"tests_passed":%d,"tests_failed":%d,"artifact_path":"%s","log_path":"%s","repro_command":"%s"}' \
        "$(json_escape "$scenario_id")" \
        "$(json_escape "$category")" \
        "$(json_escape "$PROFILE")" \
        "$(json_escape "$scenario_profiles")" \
        "$(json_escape "$test_filter")" \
        "$(json_escape "$replay_ref")" \
        "$(json_escape "$replay_extra")" \
        "$(json_escape "$unit_sentinel")" \
        "$(json_escape "$assertion_id")" \
        "$(json_escape "$run_id")" \
        "$scenario_seed" \
        "$(json_escape "$parameter_set")" \
        "$(json_escape "$status")" \
        "$rc" \
        "$duration_ms" \
        "$tests_passed" \
        "$tests_failed" \
        "$(json_escape "$scenario_log_file")" \
        "$(json_escape "$scenario_log_file")" \
        "$(json_escape "$repro_cmd")"

    if ! validate_scenario_contract "$scenario_json"; then
        contract_failure=1
        if [[ "$status" == "pass" ]]; then
            passed_count=$((passed_count - 1))
            failed_count=$((failed_count + 1))
        fi
        status="fail"
        rc=70
        printf -v scenario_json '{"schema_version":"raptorq-e2e-scenario-log-v2","scenario_id":"%s","category":"%s","profile":"%s","profile_set":"%s","test_filter":"%s","replay_ref":"%s","replay_ref_extra":"%s","unit_sentinel":"%s","assertion_id":"%s","run_id":"%s","seed":%s,"parameter_set":"%s","phase_markers":["encode","loss","decode","proof","report"],"status":"%s","exit_code":%d,"duration_ms":%d,"tests_passed":%d,"tests_failed":%d,"artifact_path":"%s","log_path":"%s","repro_command":"%s"}' \
            "$(json_escape "$scenario_id")" \
            "$(json_escape "$category")" \
            "$(json_escape "$PROFILE")" \
            "$(json_escape "$scenario_profiles")" \
            "$(json_escape "$test_filter")" \
            "$(json_escape "$replay_ref")" \
            "$(json_escape "$replay_extra")" \
            "$(json_escape "$unit_sentinel")" \
            "$(json_escape "$assertion_id")" \
            "$(json_escape "$run_id")" \
            "$scenario_seed" \
            "$(json_escape "$parameter_set")" \
            "fail" \
            "$rc" \
            "$duration_ms" \
            "$tests_passed" \
            "$tests_failed" \
            "$(json_escape "$scenario_log_file")" \
            "$(json_escape "$scenario_log_file")" \
            "$(json_escape "$repro_cmd")"
        echo "    FAIL (D7 schema contract) -> ${scenario_log_file}"
        print_scenario_contract_help
        echo "    repro: ${repro_cmd}"
    fi

    printf '%s\n' "$scenario_json" >> "$SCENARIO_LOG"

    if [[ "$contract_failure" -eq 1 ]]; then
        continue
    fi
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

if ! validate_suite_contract "$SUMMARY_FILE" "$SCENARIO_LOG"; then
    echo "FAIL (D3 forensic suite contract) -> ${SUMMARY_FILE}" >&2
    print_suite_contract_help
    exit 1
fi

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
