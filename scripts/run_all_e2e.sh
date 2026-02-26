#!/usr/bin/env bash
# Primary E2E Orchestrator (bd-26l3)
#
# Runs all subsystem E2E test suites sequentially, collects per-suite results,
# and produces a unified summary report with deterministic artifact manifests.
#
# Usage:
#   ./scripts/run_all_e2e.sh               # run all suites
#   ./scripts/run_all_e2e.sh --suite NAME   # run a single suite
#   ./scripts/run_all_e2e.sh --list         # list available suites
#   ./scripts/run_all_e2e.sh --verify-matrix # validate canonical E2E matrix
#
# Environment Variables:
#   TEST_LOG_LEVEL - error|warn|info|debug|trace (default: info)
#   RUST_LOG       - tracing filter (default: asupersync=info)
#   RUST_BACKTRACE - 1 to enable backtraces (default: 1)
#   TEST_SEED      - deterministic seed (default: 0xDEADBEEF)
#   E2E_TIMEOUT    - per-suite timeout in seconds (default: 300)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
REPORT_DIR="${PROJECT_ROOT}/target/e2e-results/orchestrator_${TIMESTAMP}"
MANIFEST_NDJSON="${REPORT_DIR}/artifact_manifest.ndjson"
MANIFEST_JSON="${REPORT_DIR}/artifact_manifest.json"
REPLAY_VERIFICATION_FILE="${REPORT_DIR}/replay_verification.json"
REPORT_FILE="${REPORT_DIR}/report.json"

export TEST_LOG_LEVEL="${TEST_LOG_LEVEL:-info}"
export RUST_LOG="${RUST_LOG:-asupersync=info}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
export TEST_SEED="${TEST_SEED:-0xDEADBEEF}"
E2E_TIMEOUT="${E2E_TIMEOUT:-300}"

# Helpers
json_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

json_bool() {
    if [[ "$1" -eq 1 ]]; then
        printf 'true'
    else
        printf 'false'
    fi
}

trim_string() {
    local value="$1"
    value="$(printf '%s' "$value" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
    printf '%s' "$value"
}

normalize_path() {
    local candidate="$1"
    candidate="$(trim_string "$candidate")"
    if [[ -z "$candidate" ]]; then
        printf ''
        return 0
    fi
    candidate="${candidate%/}"
    if [[ "$candidate" = /* ]]; then
        printf '%s' "$candidate"
    else
        printf '%s/%s' "$PROJECT_ROOT" "$candidate"
    fi
}

extract_labeled_path() {
    local log_file="$1"
    local label="$2"
    local extracted
    extracted="$(
        grep -E "^[[:space:]]*${label}[[:space:]]*:" "$log_file" 2>/dev/null \
            | tail -1 \
            | sed -E "s/^[[:space:]]*${label}[[:space:]]*:[[:space:]]*//" || true
    )"
    trim_string "$extracted"
}

latest_match_file() {
    local root="$1"
    local pattern="$2"
    local match
    if [[ ! -d "$root" ]]; then
        return 1
    fi
    match="$(
        find "$root" -type f -name "$pattern" -printf '%T@ %p\n' 2>/dev/null \
            | sort -nr \
            | head -n1 \
            | cut -d' ' -f2- || true
    )"
    match="$(trim_string "$match")"
    if [[ -n "$match" ]]; then
        printf '%s' "$match"
        return 0
    fi
    return 1
}

latest_match_dir() {
    local root="$1"
    local pattern="$2"
    local match
    if [[ ! -d "$root" ]]; then
        return 1
    fi
    match="$(
        find "$root" -type d -name "$pattern" -printf '%T@ %p\n' 2>/dev/null \
            | sort -nr \
            | head -n1 \
            | cut -d' ' -f2- || true
    )"
    match="$(trim_string "$match")"
    if [[ -n "$match" ]]; then
        printf '%s' "$match"
        return 0
    fi
    return 1
}

is_json_file() {
    local path="$1"
    [[ "$path" == *.json ]]
}

validate_suite_summary_contract() {
    local summary_file="$1"
    jq -e '
        (.schema_version | type == "string" and . == "e2e-suite-summary-v3") and
        (.suite_id | type == "string" and length > 0) and
        (.scenario_id | type == "string" and length > 0) and
        (
            (.seed | type == "string" and length > 0) or
            (.seed | type == "number")
        ) and
        (.started_ts | type == "string" and length > 0) and
        (.ended_ts | type == "string" and length > 0) and
        (.status | type == "string" and (. == "passed" or . == "failed")) and
        (.repro_command | type == "string" and length > 0) and
        (.artifact_path | type == "string" and length > 0)
    ' "$summary_file" >/dev/null 2>&1
}

# Suite definitions: name -> script path
declare -A SUITES=(
    [websocket]="test_websocket_e2e.sh"
    [http]="test_http_e2e.sh"
    [messaging]="test_messaging_e2e.sh"
    [transport]="test_transport_e2e.sh"
    [database]="test_database_e2e.sh"
    [distributed]="test_distributed_e2e.sh"
    [h2-security]="test_h2_security_e2e.sh"
    [net-hardening]="test_net_hardening_e2e.sh"
    [redis]="test_redis_e2e.sh"
    [combinators]="test_combinators.sh"
    [cancel-attribution]="test_cancel_attribution.sh"
    [scheduler]="test_scheduler_wakeup_e2e.sh"
    [phase6]="run_phase6_e2e.sh"
)

# Canonical artifact roots for manifest indexing.
declare -A SUITE_ARTIFACT_ROOTS=(
    [websocket]="target/e2e-results/websocket"
    [http]="target/e2e-results/http"
    [messaging]="target/e2e-results/messaging"
    [transport]="target/e2e-results/transport"
    [database]="target/e2e-results/database"
    [distributed]="target/e2e-results/distributed"
    [h2-security]="target/e2e-results/h2_security"
    [net-hardening]="target/e2e-results/net_hardening"
    [redis]="target/e2e-results/redis"
    [combinators]="test_logs"
    [cancel-attribution]="target/test-results/cancel-attribution"
    [scheduler]="target/e2e-results/scheduler"
    [phase6]="target/phase6-e2e"
)

# Summary file patterns used to discover suite artifacts deterministically.
declare -A SUITE_SUMMARY_GLOBS=(
    [websocket]="summary.json"
    [http]="summary.json"
    [messaging]="summary.json"
    [transport]="summary.json"
    [database]="summary.json"
    [distributed]="summary.json"
    [h2-security]="summary.json"
    [net-hardening]="summary.json"
    [redis]="summary.json"
    [combinators]="summary.json"
    [cancel-attribution]="summary_*.json"
    [scheduler]="summary.json"
    [phase6]="summary_*.json"
)

# Artifact directory patterns used when summary path is not emitted.
declare -A SUITE_ARTIFACT_DIR_GLOBS=(
    [websocket]="artifacts_*"
    [http]="artifacts_*"
    [messaging]="artifacts_*"
    [transport]="artifacts_*"
    [database]="artifacts_*"
    [distributed]="artifacts_*"
    [h2-security]="artifacts_*"
    [net-hardening]="20*"
    [redis]="artifacts_*"
    [combinators]="combinators_*"
    [cancel-attribution]=""
    [scheduler]="20*"
    [phase6]=""
)

# Canonical scenario IDs (C1/D4) for suite-level completeness tracking.
declare -A SUITE_CANONICAL_SCENARIO_ID=(
    [websocket]="E2E-SUITE-WEBSOCKET"
    [http]="E2E-SUITE-HTTP"
    [messaging]="E2E-SUITE-MESSAGING"
    [transport]="E2E-SUITE-TRANSPORT"
    [database]="E2E-SUITE-DATABASE"
    [distributed]="E2E-SUITE-DISTRIBUTED"
    [h2-security]="E2E-SUITE-H2-SECURITY"
    [net-hardening]="E2E-SUITE-NET-HARDENING"
    [redis]="E2E-SUITE-REDIS"
    [combinators]="E2E-SUITE-COMBINATORS"
    [cancel-attribution]="E2E-SUITE-CANCEL-ATTRIBUTION"
    [scheduler]="E2E-SUITE-SCHEDULER-WAKEUP"
    [phase6]="E2E-SUITE-PHASE6"
)

RAPTORQ_REQUIRED_SCENARIOS=(
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

# Ordered suite list (core subsystems first, then extended)
SUITE_ORDER=(
    websocket http messaging transport database distributed
    h2-security net-hardening redis
    combinators cancel-attribution scheduler
    phase6
)

verify_matrix_gate() {
    local matrix_report_dir="${PROJECT_ROOT}/target/e2e-results/orchestrator_${TIMESTAMP}"
    local matrix_file="${matrix_report_dir}/scenario_matrix_validation.json"
    local suite_failures=0
    local raptorq_failures=0
    local total_suite_rows=0
    local total_raptorq_rows=0

    local raptorq_script="${SCRIPT_DIR}/run_raptorq_e2e.sh"
    local raptorq_script_exists=0
    local raptorq_script_executable=0
    local raptorq_artifact_route_configured=0
    local raptorq_list_output=""

    mkdir -p "$matrix_report_dir"

    if [[ -f "$raptorq_script" ]]; then
        raptorq_script_exists=1
    fi
    if [[ -x "$raptorq_script" ]]; then
        raptorq_script_executable=1
    fi
    if [[ "$raptorq_script_exists" -eq 1 ]]; then
        if grep -q 'summary.json' "$raptorq_script" 2>/dev/null && grep -q 'scenarios.ndjson' "$raptorq_script" 2>/dev/null; then
            raptorq_artifact_route_configured=1
        fi
    fi
    if [[ "$raptorq_script_executable" -eq 1 ]]; then
        raptorq_list_output="$(bash "$raptorq_script" --list 2>/dev/null || true)"
    fi

    {
        echo "{"
        echo "  \"schema_version\": \"e2e-scenario-matrix-validation-v1\","
        echo "  \"timestamp\": \"${TIMESTAMP}\","
        echo "  \"matrix_source\": \"scripts/run_all_e2e.sh\","
        echo "  \"suite_rows\": ["
        local first_suite=1
        local name
        for name in "${SUITE_ORDER[@]}"; do
            total_suite_rows=$((total_suite_rows + 1))
            local scenario_id="${SUITE_CANONICAL_SCENARIO_ID[$name]:-}"
            local script="${SUITES[$name]}"
            local script_path="${SCRIPT_DIR}/${script}"
            local artifact_root_rel="${SUITE_ARTIFACT_ROOTS[$name]:-}"
            local artifact_root_abs
            artifact_root_abs="$(normalize_path "$artifact_root_rel")"
            local summary_glob="${SUITE_SUMMARY_GLOBS[$name]:-}"
            local artifact_dir_glob="${SUITE_ARTIFACT_DIR_GLOBS[$name]:-}"
            local script_exists=0
            local script_executable=0
            local artifact_route_configured=0
            local replay_route_configured=0
            local row_ok=1
            local replay_command="TEST_LOG_LEVEL=${TEST_LOG_LEVEL} RUST_LOG=${RUST_LOG} TEST_SEED=${TEST_SEED} E2E_TIMEOUT=${E2E_TIMEOUT} bash ${SCRIPT_DIR}/run_all_e2e.sh --suite ${name}"

            if [[ -f "$script_path" ]]; then
                script_exists=1
            fi
            if [[ -x "$script_path" ]]; then
                script_executable=1
            fi
            if [[ -n "$artifact_root_rel" && ( -n "$summary_glob" || -n "$artifact_dir_glob" ) ]]; then
                artifact_route_configured=1
            fi
            if [[ "$script_executable" -eq 1 ]]; then
                replay_route_configured=1
            fi

            if [[ -z "$scenario_id" || "$script_exists" -eq 0 || "$script_executable" -eq 0 || "$artifact_route_configured" -eq 0 || "$replay_route_configured" -eq 0 ]]; then
                row_ok=0
                suite_failures=$((suite_failures + 1))
            fi

            if [[ "$first_suite" -eq 1 ]]; then
                first_suite=0
            else
                echo ","
            fi
            printf '    {"scenario_id":"%s","suite":"%s","script":"%s","script_exists":%s,"script_executable":%s,"artifact_root":"%s","summary_glob":"%s","artifact_dir_glob":"%s","artifact_route_configured":%s,"replay_command":"%s","replay_route_configured":%s,"row_ok":%s}' \
                "$(json_escape "$scenario_id")" \
                "$(json_escape "$name")" \
                "$(json_escape "$script_path")" \
                "$(json_bool "$script_exists")" \
                "$(json_bool "$script_executable")" \
                "$(json_escape "$artifact_root_abs")" \
                "$(json_escape "$summary_glob")" \
                "$(json_escape "$artifact_dir_glob")" \
                "$(json_bool "$artifact_route_configured")" \
                "$(json_escape "$replay_command")" \
                "$(json_bool "$replay_route_configured")" \
                "$(json_bool "$row_ok")"
        done
        echo ""
        echo "  ],"
        echo "  \"raptorq_rows\": ["

        local first_raptorq=1
        local rq_id
        for rq_id in "${RAPTORQ_REQUIRED_SCENARIOS[@]}"; do
            total_raptorq_rows=$((total_raptorq_rows + 1))
            local listed=0
            local row_ok=1
            local repro_cmd="NO_PREFLIGHT=1 bash ${raptorq_script} --profile forensics --scenario ${rq_id}"

            if [[ "$raptorq_script_executable" -eq 1 && "$raptorq_list_output" == *"$rq_id"* ]]; then
                listed=1
            fi
            if [[ "$raptorq_script_executable" -eq 0 || "$raptorq_artifact_route_configured" -eq 0 || "$listed" -eq 0 ]]; then
                row_ok=0
                raptorq_failures=$((raptorq_failures + 1))
            fi

            if [[ "$first_raptorq" -eq 1 ]]; then
                first_raptorq=0
            else
                echo ","
            fi
            printf '    {"scenario_id":"%s","runner_script":"%s","script_exists":%s,"script_executable":%s,"listed_in_runner":%s,"artifact_route_configured":%s,"artifacts_expected":"summary.json,scenarios.ndjson","replay_command":"%s","row_ok":%s}' \
                "$(json_escape "$rq_id")" \
                "$(json_escape "$raptorq_script")" \
                "$(json_bool "$raptorq_script_exists")" \
                "$(json_bool "$raptorq_script_executable")" \
                "$(json_bool "$listed")" \
                "$(json_bool "$raptorq_artifact_route_configured")" \
                "$(json_escape "$repro_cmd")" \
                "$(json_bool "$row_ok")"
        done
        echo ""
        echo "  ],"

        local overall_status="pass"
        if [[ "$suite_failures" -gt 0 || "$raptorq_failures" -gt 0 ]]; then
            overall_status="fail"
        fi
        echo "  \"suite_row_count\": ${total_suite_rows},"
        echo "  \"raptorq_row_count\": ${total_raptorq_rows},"
        echo "  \"suite_failures\": ${suite_failures},"
        echo "  \"raptorq_failures\": ${raptorq_failures},"
        echo "  \"status\": \"${overall_status}\""
        echo "}"
    } > "$matrix_file"

    echo "Scenario matrix validation artifact: ${matrix_file}"
    if [[ "$suite_failures" -gt 0 || "$raptorq_failures" -gt 0 ]]; then
        echo "Scenario matrix completeness: FAILED (suite_failures=${suite_failures}, raptorq_failures=${raptorq_failures})"
        return 1
    fi
    echo "Scenario matrix completeness: PASSED (${total_suite_rows} suite rows, ${total_raptorq_rows} raptorq rows)"
    return 0
}

# --- Argument parsing ---
FILTER=""
LIST_ONLY=0
VERIFY_MATRIX_ONLY=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --list)
            LIST_ONLY=1
            shift
            ;;
        --suite)
            if [[ -z "${2:-}" ]]; then
                echo "Missing suite name after --suite" >&2
                exit 1
            fi
            FILTER="$2"
            shift 2
            ;;
        --verify-matrix)
            VERIFY_MATRIX_ONLY=1
            shift
            ;;
        *)
            echo "Unknown argument: $1" >&2
            exit 1
            ;;
    esac
done

if [[ "$LIST_ONLY" -eq 1 ]]; then
    echo "Available E2E suites:"
    for name in "${SUITE_ORDER[@]}"; do
        script="${SUITES[$name]}"
        if [ -x "${SCRIPT_DIR}/${script}" ]; then
            echo "  ${name}  (${script})"
        else
            echo "  ${name}  (${script}) [not executable]"
        fi
    done
    exit 0
fi

if [[ -n "$FILTER" && -z "${SUITES[$FILTER]+x}" ]]; then
    echo "Unknown suite: $FILTER"
    echo "Run with --list to see available suites"
    exit 1
fi

mkdir -p "$REPORT_DIR"
: > "$MANIFEST_NDJSON"

if [[ "$VERIFY_MATRIX_ONLY" -eq 1 ]]; then
    verify_matrix_gate
    exit $?
fi

echo "==================================================================="
echo "           Asupersync Primary E2E Orchestrator                      "
echo "==================================================================="
echo ""
echo "Config:"
echo "  TEST_LOG_LEVEL:  ${TEST_LOG_LEVEL}"
echo "  RUST_LOG:        ${RUST_LOG}"
echo "  TEST_SEED:       ${TEST_SEED}"
echo "  Timeout:         ${E2E_TIMEOUT}s per suite"
echo "  Timestamp:       ${TIMESTAMP}"
echo "  Report:          ${REPORT_DIR}"
echo ""
echo "-------------------------------------------------------------------"

TOTAL=0
PASS=0
FAIL=0
SKIP=0
REPLAY_UNVERIFIED=0
ARTIFACT_INCOMPLETE=0
FAILURE_CONTRACT_VIOLATIONS=0
SELF_SYNTAX_OK=1

declare -A RESULTS
declare -A EXIT_CODES
declare -A DURATION_MS
declare -a FAILURE_VIOLATION_LINES

set +e
bash -n "$SCRIPT_DIR/run_all_e2e.sh" >/dev/null 2>&1
self_syntax_rc=$?
set -e
if [[ "$self_syntax_rc" -ne 0 ]]; then
    SELF_SYNTAX_OK=0
fi

for name in "${SUITE_ORDER[@]}"; do
    if [[ -n "$FILTER" && "$name" != "$FILTER" ]]; then
        continue
    fi

    script="${SUITES[$name]}"
    script_path="${SCRIPT_DIR}/${script}"
    suite_log="${REPORT_DIR}/${name}.log"
    suite_id="${name}_e2e"
    scenario_id="${SUITE_CANONICAL_SCENARIO_ID[$name]:-}"
    replay_command="TEST_LOG_LEVEL=${TEST_LOG_LEVEL} RUST_LOG=${RUST_LOG} TEST_SEED=${TEST_SEED} E2E_TIMEOUT=${E2E_TIMEOUT} bash ${SCRIPT_DIR}/run_all_e2e.sh --suite ${name}"
    suite_start_s="$(date +%s)"
    suite_exit_code=0

    TOTAL=$((TOTAL + 1))
    printf "\n>>> %-25s" "[${name}]"

    if [ ! -x "$script_path" ]; then
        echo "SKIP (script not executable)"
        SKIP=$((SKIP + 1))
        RESULTS[$name]="SKIP"
        EXIT_CODES[$name]=127
        DURATION_MS[$name]=0
        suite_exit_code=127

        artifact_root_rel="${SUITE_ARTIFACT_ROOTS[$name]:-}"
        artifact_root_abs="$(normalize_path "$artifact_root_rel")"
        printf -v manifest_json '{"schema_version":"e2e-orchestrator-artifact-entry-v1","suite":"%s","suite_id":"%s","scenario_id":"%s","script":"%s","result":"%s","exit_code":%d,"duration_ms":%d,"suite_log":"%s","artifact_root":"%s","artifact_dir":"","summary_file":"","suite_log_found":false,"suite_log_nonempty":false,"artifact_dir_found":false,"summary_found":false,"summary_schema_required":true,"summary_schema_ok":false,"summary_schema_reason":"script_not_executable","artifact_complete":false,"replay_command":"%s","replay_script_exists":false,"replay_script_executable":false,"replay_script_syntax_ok":false,"replay_verified":false,"failure_contract_ok":false}' \
            "$(json_escape "$name")" \
            "$(json_escape "$suite_id")" \
            "$(json_escape "$scenario_id")" \
            "$(json_escape "$script_path")" \
            "SKIP" \
            127 \
            0 \
            "$(json_escape "$suite_log")" \
            "$(json_escape "$artifact_root_abs")" \
            "$(json_escape "$replay_command")"
        printf '%s\n' "$manifest_json" >> "$MANIFEST_NDJSON"
        continue
    fi

    set +e
    timeout "$E2E_TIMEOUT" bash "$script_path" > "$suite_log" 2>&1
    rc=$?
    set -e
    suite_exit_code="$rc"
    suite_end_s="$(date +%s)"
    suite_duration_ms=$(((suite_end_s - suite_start_s) * 1000))
    DURATION_MS[$name]="$suite_duration_ms"

    if [ "$rc" -eq 0 ]; then
        echo "PASS"
        PASS=$((PASS + 1))
        RESULTS[$name]="PASS"
    elif [ "$rc" -eq 124 ]; then
        echo "TIMEOUT (${E2E_TIMEOUT}s)"
        FAIL=$((FAIL + 1))
        RESULTS[$name]="TIMEOUT"
    else
        echo "FAIL (exit $rc)"
        FAIL=$((FAIL + 1))
        RESULTS[$name]="FAIL"
    fi
    EXIT_CODES[$name]="$suite_exit_code"

    artifact_root_rel="${SUITE_ARTIFACT_ROOTS[$name]:-}"
    artifact_root_abs="$(normalize_path "$artifact_root_rel")"

    summary_path="$(extract_labeled_path "$suite_log" "Summary")"
    if [[ -z "$summary_path" ]]; then
        summary_path="$(extract_labeled_path "$suite_log" "Report")"
    fi
    summary_path="$(normalize_path "$summary_path")"

    if [[ -z "$summary_path" ]]; then
        summary_glob="${SUITE_SUMMARY_GLOBS[$name]:-}"
        if [[ -n "$summary_glob" && -n "$artifact_root_abs" ]]; then
            summary_path="$(latest_match_file "$artifact_root_abs" "$summary_glob" || true)"
        fi
    fi
    summary_path="$(trim_string "$summary_path")"

    artifact_dir=""
    if [[ -n "$summary_path" && -f "$summary_path" ]]; then
        artifact_dir="$(dirname "$summary_path")"
    fi
    if [[ -z "$artifact_dir" ]]; then
        artifacts_label="$(extract_labeled_path "$suite_log" "Artifacts")"
        artifact_dir="$(normalize_path "$artifacts_label")"
    fi
    if [[ -z "$artifact_dir" ]]; then
        logs_saved_label="$(extract_labeled_path "$suite_log" "Logs saved to")"
        artifact_dir="$(normalize_path "$logs_saved_label")"
    fi
    if [[ -z "$artifact_dir" ]]; then
        logs_label="$(extract_labeled_path "$suite_log" "Logs")"
        artifact_dir="$(normalize_path "$logs_label")"
    fi
    if [[ -n "$artifact_dir" && -f "$artifact_dir" ]]; then
        artifact_dir="$(dirname "$artifact_dir")"
    fi
    if [[ -z "$artifact_dir" ]]; then
        artifact_dir_glob="${SUITE_ARTIFACT_DIR_GLOBS[$name]:-}"
        if [[ -n "$artifact_dir_glob" && -n "$artifact_root_abs" ]]; then
            artifact_dir="$(latest_match_dir "$artifact_root_abs" "$artifact_dir_glob" || true)"
        fi
    fi
    if [[ -z "$artifact_dir" && -n "$artifact_root_abs" && -d "$artifact_root_abs" ]]; then
        artifact_dir="$artifact_root_abs"
    fi
    artifact_dir="$(trim_string "$artifact_dir")"

    suite_log_found=0
    suite_log_nonempty=0
    artifact_dir_found=0
    summary_found=0
    replay_script_exists=0
    replay_script_executable=0
    replay_script_syntax_ok=0
    replay_verified=0
    artifact_complete=0
    summary_schema_required=1
    summary_schema_ok=0
    summary_schema_reason="missing_summary"
    failure_contract_ok=1

    if [[ -f "$suite_log" ]]; then
        suite_log_found=1
    fi
    if [[ -s "$suite_log" ]]; then
        suite_log_nonempty=1
    fi
    if [[ -n "$artifact_dir" && -d "$artifact_dir" ]]; then
        artifact_dir_found=1
    fi
    if [[ -n "$summary_path" && -f "$summary_path" ]]; then
        summary_found=1
    fi
    if [[ -f "$script_path" ]]; then
        replay_script_exists=1
    fi
    if [[ -x "$script_path" ]]; then
        replay_script_executable=1
    fi

    set +e
    bash -n "$script_path" >/dev/null 2>&1
    script_syntax_rc=$?
    set -e
    if [[ "$script_syntax_rc" -eq 0 && "$SELF_SYNTAX_OK" -eq 1 ]]; then
        replay_script_syntax_ok=1
    fi

    if [[ "$replay_script_exists" -eq 1 && "$replay_script_executable" -eq 1 && "$replay_script_syntax_ok" -eq 1 ]]; then
        replay_verified=1
    fi

    if [[ "$suite_log_found" -eq 1 && "$suite_log_nonempty" -eq 1 && "$artifact_dir_found" -eq 1 && "$summary_found" -eq 1 ]]; then
        artifact_complete=1
    fi

    if [[ "$summary_found" -eq 1 ]]; then
        if is_json_file "$summary_path"; then
            if validate_suite_summary_contract "$summary_path"; then
                summary_schema_ok=1
                summary_schema_reason="ok"
            else
                summary_schema_reason="schema_drift"
            fi
        else
            summary_schema_reason="non_json_summary"
        fi
    fi

    contract_violation=0
    if [[ "$summary_schema_ok" -eq 0 ]]; then
        contract_violation=1
    fi
    if [[ "${RESULTS[$name]}" == "FAIL" || "${RESULTS[$name]}" == "TIMEOUT" ]]; then
        if [[ "$replay_verified" -eq 0 || "$artifact_complete" -eq 0 ]]; then
            contract_violation=1
        fi
    fi
    if [[ "$contract_violation" -eq 1 ]]; then
        failure_contract_ok=0
        FAILURE_CONTRACT_VIOLATIONS=$((FAILURE_CONTRACT_VIOLATIONS + 1))
        FAILURE_VIOLATION_LINES+=("$name")
    fi

    if [[ "$replay_verified" -eq 0 ]]; then
        REPLAY_UNVERIFIED=$((REPLAY_UNVERIFIED + 1))
    fi
    if [[ "$artifact_complete" -eq 0 ]]; then
        ARTIFACT_INCOMPLETE=$((ARTIFACT_INCOMPLETE + 1))
    fi

    printf -v manifest_json '{"schema_version":"e2e-orchestrator-artifact-entry-v1","suite":"%s","suite_id":"%s","scenario_id":"%s","script":"%s","result":"%s","exit_code":%d,"duration_ms":%d,"suite_log":"%s","artifact_root":"%s","artifact_dir":"%s","summary_file":"%s","suite_log_found":%s,"suite_log_nonempty":%s,"artifact_dir_found":%s,"summary_found":%s,"summary_schema_required":%s,"summary_schema_ok":%s,"summary_schema_reason":"%s","artifact_complete":%s,"replay_command":"%s","replay_script_exists":%s,"replay_script_executable":%s,"replay_script_syntax_ok":%s,"replay_verified":%s,"failure_contract_ok":%s}' \
        "$(json_escape "$name")" \
        "$(json_escape "$suite_id")" \
        "$(json_escape "$scenario_id")" \
        "$(json_escape "$script_path")" \
        "$(json_escape "${RESULTS[$name]}")" \
        "$suite_exit_code" \
        "$suite_duration_ms" \
        "$(json_escape "$suite_log")" \
        "$(json_escape "$artifact_root_abs")" \
        "$(json_escape "$artifact_dir")" \
        "$(json_escape "$summary_path")" \
        "$(json_bool "$suite_log_found")" \
        "$(json_bool "$suite_log_nonempty")" \
        "$(json_bool "$artifact_dir_found")" \
        "$(json_bool "$summary_found")" \
        "$(json_bool "$summary_schema_required")" \
        "$(json_bool "$summary_schema_ok")" \
        "$(json_escape "$summary_schema_reason")" \
        "$(json_bool "$artifact_complete")" \
        "$(json_escape "$replay_command")" \
        "$(json_bool "$replay_script_exists")" \
        "$(json_bool "$replay_script_executable")" \
        "$(json_bool "$replay_script_syntax_ok")" \
        "$(json_bool "$replay_verified")" \
        "$(json_bool "$failure_contract_ok")"
    printf '%s\n' "$manifest_json" >> "$MANIFEST_NDJSON"
done

# --- Build deterministic manifest/index files ---
{
    echo "["
    first=1
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        if [[ "$first" -eq 1 ]]; then
            first=0
        else
            echo ","
        fi
        printf "  %s" "$line"
    done < "$MANIFEST_NDJSON"
    echo ""
    echo "]"
} > "$MANIFEST_JSON"

verification_status="pass"
if [[ "$FAILURE_CONTRACT_VIOLATIONS" -gt 0 ]]; then
    verification_status="fail"
fi

{
    echo "{"
    echo "  \"schema_version\": \"e2e-replay-verification-v1\","
    echo "  \"timestamp\": \"${TIMESTAMP}\","
    echo "  \"report_dir\": \"$(json_escape "$REPORT_DIR")\","
    echo "  \"total_suites\": ${TOTAL},"
    echo "  \"failed_suites\": ${FAIL},"
    echo "  \"replay_unverified_count\": ${REPLAY_UNVERIFIED},"
    echo "  \"artifact_incomplete_count\": ${ARTIFACT_INCOMPLETE},"
    echo "  \"failure_contract_violations\": ${FAILURE_CONTRACT_VIOLATIONS},"
    echo "  \"status\": \"${verification_status}\","
    echo "  \"violating_suites\": ["
    if [[ "${#FAILURE_VIOLATION_LINES[@]}" -gt 0 ]]; then
        for idx in "${!FAILURE_VIOLATION_LINES[@]}"; do
            if [[ "$idx" -gt 0 ]]; then
                echo ","
            fi
            printf "    \"%s\"" "$(json_escape "${FAILURE_VIOLATION_LINES[$idx]}")"
        done
        echo ""
    fi
    echo "  ],"
    echo "  \"manifest_ndjson\": \"$(json_escape "$MANIFEST_NDJSON")\","
    echo "  \"manifest_json\": \"$(json_escape "$MANIFEST_JSON")\""
    echo "}"
} > "$REPLAY_VERIFICATION_FILE"

# --- Generate summary report ---
{
    echo "{"
    echo "  \"timestamp\": \"${TIMESTAMP}\","
    echo "  \"seed\": \"${TEST_SEED}\","
    echo "  \"test_log_level\": \"${TEST_LOG_LEVEL}\","
    echo "  \"total\": ${TOTAL},"
    echo "  \"passed\": ${PASS},"
    echo "  \"failed\": ${FAIL},"
    echo "  \"skipped\": ${SKIP},"
    echo "  \"manifest_ndjson\": \"$(json_escape "$MANIFEST_NDJSON")\","
    echo "  \"manifest_json\": \"$(json_escape "$MANIFEST_JSON")\","
    echo "  \"replay_verification\": \"$(json_escape "$REPLAY_VERIFICATION_FILE")\","
    echo "  \"suites\": {"
    first=true
    for name in "${SUITE_ORDER[@]}"; do
        if [[ -n "$FILTER" && "$name" != "$FILTER" ]]; then
            continue
        fi
        result="${RESULTS[$name]:-SKIP}"
        if [ "$first" = true ]; then
            first=false
        else
            echo ","
        fi
        printf "    \"%s\": \"%s\"" "$name" "$result"
    done
    echo ""
    echo "  }"
    echo "}"
} > "$REPORT_FILE"

# --- Summary ---
echo ""
echo "==================================================================="
echo "                   PRIMARY E2E SUMMARY                              "
echo "==================================================================="
echo ""
echo "  Seed:     ${TEST_SEED}"
echo "  Suites:   ${TOTAL} total"
echo "  Passed:   ${PASS}"
echo "  Failed:   ${FAIL}"
echo "  Skipped:  ${SKIP}"
echo ""

for name in "${SUITE_ORDER[@]}"; do
    if [[ -n "$FILTER" && "$name" != "$FILTER" ]]; then
        continue
    fi
    result="${RESULTS[$name]:-SKIP}"
    printf "  %-25s %s\n" "$name" "$result"
done

echo ""
echo "  Report:   ${REPORT_FILE}"
echo "  Logs:     ${REPORT_DIR}/"
echo "  Manifest: ${MANIFEST_JSON}"
echo "  Replay:   ${REPLAY_VERIFICATION_FILE}"
echo ""

if [ "$FAILURE_CONTRACT_VIOLATIONS" -gt 0 ]; then
    echo "  Artifact contract: FAILED (${FAILURE_CONTRACT_VIOLATIONS} violating suite(s))"
    echo "==================================================================="
    exit 2
fi

if [ "$FAIL" -gt 0 ]; then
    echo "  Status: FAILED"
    echo "==================================================================="
    exit 1
fi

echo "  Status: PASSED"
echo "==================================================================="
