#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
ARTIFACT="${PROJECT_ROOT}/artifacts/otlp_audit_cluster_inventory_v1.json"
MODE="dry-run"
SCENARIO=""
OUTPUT_ROOT_OVERRIDE="${OTLP_AUDIT_INVENTORY_OUTPUT_DIR:-}"
RUN_ID_OVERRIDE="${OTLP_AUDIT_INVENTORY_RUN_ID:-}"

usage() {
    cat <<'USAGE'
Usage: ./scripts/run_otlp_audit_inventory_smoke.sh [options]

Options:
  --list                    List scenario IDs
  --scenario <id>           Run a specific scenario
  --dry-run                 Inventory proof without invoking cargo (default)
  --execute                 Same inventory proof, with execute-mode metadata
  --output-root <dir>       Override output root
  -h, --help                Show this help text
USAGE
}

require_tools() {
    local missing=0
    for tool in awk date find git jq sed sha256sum; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            echo "FATAL: missing required tool: $tool" >&2
            missing=1
        fi
    done
    if [ "$missing" -ne 0 ]; then
        exit 1
    fi
    if [ ! -f "$ARTIFACT" ]; then
        echo "FATAL: missing OTLP audit inventory artifact: $ARTIFACT" >&2
        exit 1
    fi
}

json_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

artifact_value() {
    jq -r "$1" "$ARTIFACT"
}

require_target_dir_rch_cargo_command() {
    local label="$1"
    local command="$2"

    if [[ "$command" == rch\ exec\ --\ cargo\ * ]]; then
        echo "FATAL: $label must use rch exec with env CARGO_TARGET_DIR before cargo, not bare rch cargo" >&2
        exit 1
    fi
    if [[ "$command" != rch\ exec\ --\ env\ *CARGO_TARGET_DIR=* ]]; then
        echo "FATAL: $label is missing CARGO_TARGET_DIR routing: $command" >&2
        exit 1
    fi
    if [[ "$command" != *" cargo "* ]]; then
        echo "FATAL: $label must route cargo through rch env: $command" >&2
        exit 1
    fi
}

default_scenario_id() {
    jq -r '.smoke_scenarios[0].scenario_id' "$ARTIFACT"
}

list_scenarios() {
    jq -r '.smoke_scenarios[] | [.scenario_id, .description] | @tsv' "$ARTIFACT"
}

load_scenario_json() {
    local scenario_id="$1"
    jq -c --arg scenario_id "$scenario_id" '.smoke_scenarios[] | select(.scenario_id == $scenario_id)' "$ARTIFACT"
}

lookup_inventory_field() {
    local path="$1"
    local field="$2"
    jq -r --arg path "$path" --arg field "$field" \
        '.preserved_untracked_files[]? | select(.path == $path) | .[$field] // empty' \
        "$ARTIFACT"
}

is_inventory_path() {
    local path="$1"
    jq -e --arg path "$path" '.preserved_untracked_files[]? | select(.path == $path)' "$ARTIFACT" >/dev/null
}

is_tracked_path() {
    local path="$1"
    git -C "$PROJECT_ROOT" ls-files --error-unmatch "$path" >/dev/null 2>&1
}

is_module_declared() {
    local path="$1"
    local module_name
    module_name="$(basename "$path" .rs)"
    grep -Eq "^[[:space:]]*pub[[:space:]]+mod[[:space:]]+${module_name};" \
        "$PROJECT_ROOT/src/observability/mod.rs"
}

write_current_file_report() {
    local report_path="$1"
    local first=1
    printf '[' >"$report_path"
    while IFS= read -r abs_path; do
        local path tracked in_inventory owner invariant seam dedup status module_declared git_state
        path="${abs_path#${PROJECT_ROOT}/}"
        tracked=false
        git_state="untracked"
        if is_tracked_path "$path"; then
            tracked=true
            git_state="tracked"
        fi

        in_inventory=false
        owner="tracked_existing_coverage"
        invariant="tracked_existing_otlp_audit_coverage"
        seam="tracked_existing_production_seam"
        dedup="tracked_existing_coverage_not_owned_by_this_blocker"
        status="tracked_existing"
        if is_inventory_path "$path"; then
            in_inventory=true
            owner="$(lookup_inventory_field "$path" owner_bead)"
            invariant="$(lookup_inventory_field "$path" invariant)"
            seam="$(lookup_inventory_field "$path" production_seam)"
            dedup="$(lookup_inventory_field "$path" deduplication_decision)"
            status="$(lookup_inventory_field "$path" status)"
        elif [ "$tracked" = false ]; then
            owner="unmapped"
            invariant="unmapped_untracked_otlp_audit_file"
            seam="unmapped"
            dedup="none"
            status="unexplained_untracked"
        fi

        module_declared=false
        if is_module_declared "$path"; then
            module_declared=true
        fi

        if [ "$first" -eq 0 ]; then
            printf ',\n' >>"$report_path"
        fi
        first=0
        cat >>"$report_path" <<JSON
  {
    "path": "$(json_escape "$path")",
    "git_state": "$(json_escape "$git_state")",
    "owner_bead": "$(json_escape "$owner")",
    "invariant": "$(json_escape "$invariant")",
    "production_seam": "$(json_escape "$seam")",
    "deduplication_decision": "$(json_escape "$dedup")",
    "status": "$(json_escape "$status")",
    "module_declared": ${module_declared}
  }
JSON
    done < <(find "$PROJECT_ROOT/src/observability" -maxdepth 1 -type f -name 'otlp_*_audit_test.rs' | sort)
    printf '\n]\n' >>"$report_path"
}

write_missing_preserved_report() {
    local report_path="$1"
    local first=1
    printf '[' >"$report_path"
    while IFS= read -r path; do
        if [ -f "$PROJECT_ROOT/$path" ]; then
            continue
        fi
        if [ "$first" -eq 0 ]; then
            printf ',\n' >>"$report_path"
        fi
        first=0
        printf '  "%s"' "$(json_escape "$path")" >>"$report_path"
    done < <(jq -r '.preserved_untracked_files[].path' "$ARTIFACT")
    printf '\n]\n' >>"$report_path"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --list)
            require_tools
            list_scenarios
            exit 0
            ;;
        --scenario)
            SCENARIO="${2:-}"
            shift 2
            ;;
        --dry-run)
            MODE="dry-run"
            shift
            ;;
        --execute)
            MODE="execute"
            shift
            ;;
        --output-root)
            OUTPUT_ROOT_OVERRIDE="${2:-}"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

require_tools

if [ -z "$SCENARIO" ]; then
    SCENARIO="$(default_scenario_id)"
fi

SCENARIO_JSON="$(load_scenario_json "$SCENARIO")"
if [ -z "$SCENARIO_JSON" ]; then
    echo "FATAL: unknown scenario id: $SCENARIO" >&2
    exit 1
fi

OUTPUT_ROOT="${OUTPUT_ROOT_OVERRIDE:-$(jq -r '.output_root' <<<"$SCENARIO_JSON")}"
RUN_ID="${RUN_ID_OVERRIDE:-$(date +%Y%m%d_%H%M%S)}"
RUN_DIR="${PROJECT_ROOT}/${OUTPUT_ROOT}/run_${RUN_ID}/${SCENARIO}"
RUN_LOG_PATH="${RUN_DIR}/run.log"
FILE_REPORT_PATH="${RUN_DIR}/otlp_audit_file_report.json"
MISSING_REPORT_PATH="${RUN_DIR}/missing_preserved_files.json"
RCH_QUEUE_SNAPSHOT_PATH="${RUN_DIR}/rch_queue_snapshot.txt"
RUN_REPORT_PATH="${RUN_DIR}/run_report.json"
mkdir -p "$RUN_DIR"

STARTED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
SOURCE_REPO_HASH="$(git -C "$PROJECT_ROOT" rev-parse --short=12 HEAD 2>/dev/null || printf unknown)"
GIT_BRANCH="$(git -C "$PROJECT_ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null || printf unknown)"
GIT_UPSTREAM="$(git -C "$PROJECT_ROOT" rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null || printf none)"

if command -v rch >/dev/null 2>&1; then
    rch queue >"$RCH_QUEUE_SNAPSHOT_PATH" 2>&1 || true
else
    printf 'rch unavailable\n' >"$RCH_QUEUE_SNAPSHOT_PATH"
fi

write_current_file_report "$FILE_REPORT_PATH"
write_missing_preserved_report "$MISSING_REPORT_PATH"

EXPECTED_PRESERVED_FILE_COUNT="$(jq -r '.smoke_scenarios[0].expected_preserved_file_count' "$ARTIFACT")"
TOTAL_OTLP_AUDIT_FILE_COUNT="$(jq 'length' "$FILE_REPORT_PATH")"
TRACKED_OTLP_AUDIT_FILE_COUNT="$(jq '[.[] | select(.git_state == "tracked")] | length' "$FILE_REPORT_PATH")"
PRESERVED_MAPPED_FILE_COUNT="$(jq --arg blocker "$(artifact_value '.blocker_bead_id')" '[.[] | select(.owner_bead == $blocker)] | length' "$FILE_REPORT_PATH")"
PRESERVED_UNTRACKED_FILE_COUNT="$(jq --arg blocker "$(artifact_value '.blocker_bead_id')" '[.[] | select(.git_state == "untracked" and .owner_bead == $blocker)] | length' "$FILE_REPORT_PATH")"
UNEXPLAINED_UNTRACKED_FILE_COUNT="$(jq '[.[] | select(.git_state == "untracked" and .owner_bead == "unmapped")] | length' "$FILE_REPORT_PATH")"
MISSING_PRESERVED_FILE_COUNT="$(jq 'length' "$MISSING_REPORT_PATH")"
MODULE_DECLARED_BLOCKED_FILE_COUNT="$(jq --arg blocker "$(artifact_value '.blocker_bead_id')" '[.[] | select(.owner_bead == $blocker and .module_declared == true and (.status | startswith("blocked")))] | length' "$FILE_REPORT_PATH")"
INVARIANT_NAMES_JSON="$(jq '[.preserved_untracked_files[].invariant] | unique' "$ARTIFACT")"
PRODUCTION_SEAMS_JSON="$(jq '[.preserved_untracked_files[].production_seam] | unique' "$ARTIFACT")"
DEDUPLICATION_DECISIONS_JSON="$(jq '[.preserved_untracked_files[].deduplication_decision] | unique' "$ARTIFACT")"
OWNER_BEADS_JSON="$(jq '[.blocker_bead_id] | unique' "$ARTIFACT")"
FEATURE_FLAGS_JSON="$(jq '.feature_flags' "$ARTIFACT")"
SANITIZED_ENDPOINT_CONFIG_JSON="$(jq '.sanitized_endpoint_config' "$ARTIFACT")"
EMITTED_COUNTERS_JSON="$(jq '.emitted_otlp_counters' "$ARTIFACT")"
PRODUCTION_LIB_CHECK_COMMAND="$(artifact_value '.proof_commands.production_lib_check')"
BLOCKED_FULL_TEST_CHECK_COMMAND="$(artifact_value '.proof_commands.blocked_full_test_check')"
require_target_dir_rch_cargo_command "proof_commands.production_lib_check" "$PRODUCTION_LIB_CHECK_COMMAND"
require_target_dir_rch_cargo_command "proof_commands.blocked_full_test_check" "$BLOCKED_FULL_TEST_CHECK_COMMAND"
ARTIFACT_SHA256="$(sha256sum "$ARTIFACT" | awk '{print $1}')"

VALIDATION_PASSED=false
FINAL_VERDICT="blocked_inventory_failed"
SCRIPT_EXIT_CODE=1
if [ "$PRESERVED_MAPPED_FILE_COUNT" -eq "$EXPECTED_PRESERVED_FILE_COUNT" ] \
    && [ "$UNEXPLAINED_UNTRACKED_FILE_COUNT" -eq 0 ] \
    && [ "$MISSING_PRESERVED_FILE_COUNT" -eq 0 ] \
    && [ "$MODULE_DECLARED_BLOCKED_FILE_COUNT" -eq 0 ]; then
    VALIDATION_PASSED=true
    FINAL_VERDICT="passed_inventory_fail_closed_to_${BLOCKER_BEAD_ID:-$(artifact_value '.blocker_bead_id')}"
    SCRIPT_EXIT_CODE=0
fi

ENDED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

jq -n \
    --arg schema_version "otlp-audit-inventory-smoke-report-v1" \
    --arg scenario_id "$SCENARIO" \
    --arg mode "$MODE" \
    --arg started_at "$STARTED_TS" \
    --arg ended_at "$ENDED_TS" \
    --arg source_repo_hash "$SOURCE_REPO_HASH" \
    --arg git_branch "$GIT_BRANCH" \
    --arg git_upstream "$GIT_UPSTREAM" \
    --arg inventory_artifact_path "$ARTIFACT" \
    --arg inventory_artifact_sha256 "$ARTIFACT_SHA256" \
    --arg run_dir "$RUN_DIR" \
    --arg rch_queue_snapshot_path "$RCH_QUEUE_SNAPSHOT_PATH" \
    --arg production_lib_check_command "$PRODUCTION_LIB_CHECK_COMMAND" \
    --arg blocked_full_test_check_command "$BLOCKED_FULL_TEST_CHECK_COMMAND" \
    --arg file_report_path "$FILE_REPORT_PATH" \
    --arg missing_preserved_report_path "$MISSING_REPORT_PATH" \
    --arg run_report_path "$RUN_REPORT_PATH" \
    --arg run_log_path "$RUN_LOG_PATH" \
    --arg final_verdict "$FINAL_VERDICT" \
    --argjson validation_passed "$VALIDATION_PASSED" \
    --argjson script_exit_code "$SCRIPT_EXIT_CODE" \
    --argjson total_otlp_audit_file_count "$TOTAL_OTLP_AUDIT_FILE_COUNT" \
    --argjson tracked_otlp_audit_file_count "$TRACKED_OTLP_AUDIT_FILE_COUNT" \
    --argjson preserved_mapped_file_count "$PRESERVED_MAPPED_FILE_COUNT" \
    --argjson preserved_untracked_file_count "$PRESERVED_UNTRACKED_FILE_COUNT" \
    --argjson expected_preserved_file_count "$EXPECTED_PRESERVED_FILE_COUNT" \
    --argjson unexplained_untracked_file_count "$UNEXPLAINED_UNTRACKED_FILE_COUNT" \
    --argjson missing_preserved_file_count "$MISSING_PRESERVED_FILE_COUNT" \
    --argjson module_declared_blocked_file_count "$MODULE_DECLARED_BLOCKED_FILE_COUNT" \
    --argjson owner_beads "$OWNER_BEADS_JSON" \
    --argjson invariant_names "$INVARIANT_NAMES_JSON" \
    --argjson production_seams "$PRODUCTION_SEAMS_JSON" \
    --argjson feature_flags "$FEATURE_FLAGS_JSON" \
    --argjson sanitized_endpoint_config "$SANITIZED_ENDPOINT_CONFIG_JSON" \
    --argjson emitted_otlp_counters "$EMITTED_COUNTERS_JSON" \
    --argjson retry_drop_recovery_counters "$EMITTED_COUNTERS_JSON" \
    --argjson deduplication_decisions "$DEDUPLICATION_DECISIONS_JSON" \
    '{
        schema_version: $schema_version,
        scenario_id: $scenario_id,
        mode: $mode,
        started_at: $started_at,
        ended_at: $ended_at,
        source_repo_hash: $source_repo_hash,
        git_branch: $git_branch,
        git_upstream: $git_upstream,
        inventory_artifact_path: $inventory_artifact_path,
        inventory_artifact_sha256: $inventory_artifact_sha256,
        run_dir: $run_dir,
        rch_queue_snapshot_path: $rch_queue_snapshot_path,
        production_lib_check_command: $production_lib_check_command,
        blocked_full_test_check_command: $blocked_full_test_check_command,
        total_otlp_audit_file_count: $total_otlp_audit_file_count,
        tracked_otlp_audit_file_count: $tracked_otlp_audit_file_count,
        preserved_mapped_file_count: $preserved_mapped_file_count,
        preserved_untracked_file_count: $preserved_untracked_file_count,
        expected_preserved_file_count: $expected_preserved_file_count,
        unexplained_untracked_file_count: $unexplained_untracked_file_count,
        missing_preserved_file_count: $missing_preserved_file_count,
        module_declared_blocked_file_count: $module_declared_blocked_file_count,
        owner_beads: $owner_beads,
        invariant_names: $invariant_names,
        production_seams: $production_seams,
        feature_flags: $feature_flags,
        sanitized_endpoint_config: $sanitized_endpoint_config,
        emitted_otlp_counters: $emitted_otlp_counters,
        retry_drop_recovery_counters: $retry_drop_recovery_counters,
        cancellation_fallback_state: "preserved_untracked_tests_block_downstream_signoff_until_normalized",
        deduplication_decisions: $deduplication_decisions,
        artifact_paths: {
            file_report_path: $file_report_path,
            missing_preserved_report_path: $missing_preserved_report_path,
            rch_queue_snapshot_path: $rch_queue_snapshot_path,
            run_report_path: $run_report_path,
            run_log_path: $run_log_path
        },
        validation_passed: $validation_passed,
        script_exit_code: $script_exit_code,
        final_verdict: $final_verdict
    }' >"$RUN_REPORT_PATH"

{
    printf 'scenario_id=%s\n' "$SCENARIO"
    printf 'schema_version=%s\n' "$(artifact_value '.schema_version')"
    printf 'source_repo_hash=%s\n' "$SOURCE_REPO_HASH"
    printf 'git_branch=%s\n' "$GIT_BRANCH"
    printf 'git_upstream=%s\n' "$GIT_UPSTREAM"
    printf 'inventory_artifact_path=%s\n' "$ARTIFACT"
    printf 'run_dir=%s\n' "$RUN_DIR"
    printf 'rch_queue_snapshot_path=%s\n' "$RCH_QUEUE_SNAPSHOT_PATH"
    printf 'production_lib_check_command=%s\n' "$PRODUCTION_LIB_CHECK_COMMAND"
    printf 'blocked_full_test_check_command=%s\n' "$BLOCKED_FULL_TEST_CHECK_COMMAND"
    printf 'total_otlp_audit_file_count=%s\n' "$TOTAL_OTLP_AUDIT_FILE_COUNT"
    printf 'tracked_otlp_audit_file_count=%s\n' "$TRACKED_OTLP_AUDIT_FILE_COUNT"
    printf 'preserved_mapped_file_count=%s\n' "$PRESERVED_MAPPED_FILE_COUNT"
    printf 'preserved_untracked_file_count=%s\n' "$PRESERVED_UNTRACKED_FILE_COUNT"
    printf 'expected_preserved_file_count=%s\n' "$EXPECTED_PRESERVED_FILE_COUNT"
    printf 'unexplained_untracked_file_count=%s\n' "$UNEXPLAINED_UNTRACKED_FILE_COUNT"
    printf 'missing_preserved_file_count=%s\n' "$MISSING_PRESERVED_FILE_COUNT"
    printf 'module_declared_blocked_file_count=%s\n' "$MODULE_DECLARED_BLOCKED_FILE_COUNT"
    printf 'owner_beads=%s\n' "$OWNER_BEADS_JSON"
    printf 'feature_flags=%s\n' "$FEATURE_FLAGS_JSON"
    printf 'sanitized_endpoint_config=%s\n' "$SANITIZED_ENDPOINT_CONFIG_JSON"
    printf 'emitted_otlp_counters=%s\n' "$EMITTED_COUNTERS_JSON"
    printf 'retry_drop_recovery_counters=%s\n' "$EMITTED_COUNTERS_JSON"
    printf 'cancellation_fallback_state=%s\n' "preserved_untracked_tests_block_downstream_signoff_until_normalized"
    printf 'artifact_paths=%s\n' "$RUN_REPORT_PATH"
    printf 'final_verdict=%s\n' "$FINAL_VERDICT"
} >"$RUN_LOG_PATH"

cat "$RUN_REPORT_PATH"
exit "$SCRIPT_EXIT_CODE"
