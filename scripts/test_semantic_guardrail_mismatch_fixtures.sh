#!/usr/bin/env bash
# SEM-10.4: Intentional mismatch fixture harness for semantic guardrails.
#
# Validates that CI guardrail scripts and the unified semantic runner fail with
# precise, actionable diagnostics under controlled mismatch injections.
#
# Usage:
#   scripts/test_semantic_guardrail_mismatch_fixtures.sh [--light] [--fixture-id <id>] [--no-rch] [--keep-workdirs]
#
# Defaults:
#   - Runs all fixture cases from tests/fixtures/semantic_guardrail_mismatch/fixtures.json
#   - Uses rch for heavy runner cases when available
#   - Writes artifacts under target/semantic-guardrail-fixtures/<run-id>
#   - Materializes a HEAD snapshot workspace per case without registering git worktrees
#
# Environment:
#   - SEM_GUARDRAIL_ARTIFACT_ROOT: override artifact root directory.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
FIXTURE_FILE="$PROJECT_ROOT/tests/fixtures/semantic_guardrail_mismatch/fixtures.json"
ARTIFACT_ROOT="${SEM_GUARDRAIL_ARTIFACT_ROOT:-$PROJECT_ROOT/target/semantic-guardrail-fixtures}"

LIGHT_ONLY=false
NO_RCH=false
KEEP_WORKDIRS=false
FIXTURE_FILTER=""

usage() {
    cat <<'USAGE'
Usage: scripts/test_semantic_guardrail_mismatch_fixtures.sh [options]

Options:
  --light                 Skip heavy fixture cases (runner/cargo-backed cases).
  --fixture-id <id>       Run only one fixture id.
  --no-rch                Disable rch even for heavy cases.
  --keep-workdirs         Compatibility no-op; snapshot workspaces are retained under the run dir.
  -h, --help              Show this help.

Environment:
  SEM_GUARDRAIL_ARTIFACT_ROOT
                          Override artifact output root
                          (default: <project>/target/semantic-guardrail-fixtures).
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --light)
            LIGHT_ONLY=true
            shift
            ;;
        --fixture-id)
            FIXTURE_FILTER="${2:-}"
            shift 2
            ;;
        --no-rch)
            NO_RCH=true
            shift
            ;;
        --keep-workdirs)
            KEEP_WORKDIRS=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage
            exit 2
            ;;
    esac
done

# Fixture runs must stay local and must not register worktrees against shared main.
export BEADS_NO_DAEMON=1

if ! command -v jq >/dev/null 2>&1; then
    echo "FATAL: jq is required" >&2
    exit 2
fi
if ! command -v git >/dev/null 2>&1; then
    echo "FATAL: git is required" >&2
    exit 2
fi
if [[ ! -f "$FIXTURE_FILE" ]]; then
    echo "FATAL: fixture file missing at $FIXTURE_FILE" >&2
    exit 2
fi

SCHEMA_VERSION="$(jq -r '.schema_version // empty' "$FIXTURE_FILE")"
if [[ "$SCHEMA_VERSION" != "semantic-guardrail-mismatch-fixtures-v1" ]]; then
    echo "FATAL: unsupported fixture schema_version '$SCHEMA_VERSION'" >&2
    exit 2
fi

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="$ARTIFACT_ROOT/$RUN_ID"
LOG_DIR="$RUN_DIR/logs"
WORK_DIR="$RUN_DIR/workspaces"
mkdir -p "$LOG_DIR" "$WORK_DIR"

REPORT_NDJSON="$RUN_DIR/case_reports.ndjson"
REPORT_JSON="$RUN_DIR/summary.json"

ensure_artifact_dirs() {
    mkdir -p "$RUN_DIR" "$LOG_DIR" "$WORK_DIR"
}

prepare_case_workspace() {
    local case_workspace="$1"
    local case_index="$2"

    mkdir -p "$case_workspace" "$(dirname "$case_index")"
    : >"$case_index"
    GIT_INDEX_FILE="$case_index" git -C "$PROJECT_ROOT" read-tree HEAD
    GIT_INDEX_FILE="$case_index" GIT_WORK_TREE="$case_workspace" \
        git -C "$PROJECT_ROOT" checkout-index --all --force
}

parse_command_args() {
    local command_str="$1"

    if [[ -z "$command_str" || "$command_str" == *$'\n'* ]]; then
        echo "FATAL: unsupported empty or multi-line fixture command: $command_str" >&2
        return 1
    fi

    case "$command_str" in
        *'&&'*|*'||'*|*';'*|*'|'*|*'<'*|*'>'*|*'$('*|*'`'*|*'"'*|*"'"*)
            echo "FATAL: unsupported shell syntax in fixture command: $command_str" >&2
            return 1
            ;;
    esac

    COMMAND_ARGS=()
    read -r -a COMMAND_ARGS <<<"$command_str"
    if [[ ${#COMMAND_ARGS[@]} -eq 0 ]]; then
        echo "FATAL: failed to parse fixture command: $command_str" >&2
        return 1
    fi
}

if [[ -n "$FIXTURE_FILTER" ]]; then
    mapfile -t CASE_IDS < <(jq -r --arg id "$FIXTURE_FILTER" '.cases[] | select(.fixture_id == $id) | .fixture_id' "$FIXTURE_FILE")
    if [[ ${#CASE_IDS[@]} -eq 0 ]]; then
        echo "FATAL: fixture-id not found: $FIXTURE_FILTER" >&2
        exit 2
    fi
else
    mapfile -t CASE_IDS < <(jq -r '.cases[].fixture_id' "$FIXTURE_FILE")
fi

if [[ ${#CASE_IDS[@]} -eq 0 ]]; then
    echo "FATAL: no fixture cases selected" >&2
    exit 2
fi

printf '=== SEM-10.4 mismatch fixture harness ===\n'
printf 'Run id: %s\n' "$RUN_ID"
printf 'Fixture file: %s\n' "$FIXTURE_FILE"
printf 'Selected cases: %s\n\n' "${#CASE_IDS[@]}"

pass_count=0
fail_count=0
skip_count=0

for case_id in "${CASE_IDS[@]}"; do
    ensure_artifact_dirs

    heavy="$(jq -r --arg id "$case_id" '.cases[] | select(.fixture_id == $id) | .heavy' "$FIXTURE_FILE")"
    run_via_rch="$(jq -r --arg id "$case_id" '.cases[] | select(.fixture_id == $id) | .run_via_rch' "$FIXTURE_FILE")"
    surface="$(jq -r --arg id "$case_id" '.cases[] | select(.fixture_id == $id) | .surface' "$FIXTURE_FILE")"
    purpose="$(jq -r --arg id "$case_id" '.cases[] | select(.fixture_id == $id) | .purpose' "$FIXTURE_FILE")"

    if [[ "$LIGHT_ONLY" == "true" && "$heavy" == "true" ]]; then
        printf '[SKIP] %s (%s): heavy fixture skipped by --light\n' "$case_id" "$surface"
        mkdir -p "$(dirname "$REPORT_NDJSON")"
        jq -n \
            --arg fixture_id "$case_id" \
            --arg surface "$surface" \
            --arg purpose "$purpose" \
            '{fixture_id:$fixture_id,surface:$surface,purpose:$purpose,status:"skipped",reason:"light_mode",exit_code:null,expected_exit:null,diagnostic_checks:[]}' \
            >> "$REPORT_NDJSON"
        skip_count=$((skip_count + 1))
        continue
    fi

    case_workspace="$WORK_DIR/$case_id"
    case_index="$RUN_DIR/indexes/${case_id}.index"
    prepare_case_workspace "$case_workspace" "$case_index"

    mutation_op="$(jq -r --arg id "$case_id" '.cases[] | select(.fixture_id == $id) | .mutation.operation' "$FIXTURE_FILE")"
    mutation_file_rel="$(jq -r --arg id "$case_id" '.cases[] | select(.fixture_id == $id) | .mutation.file' "$FIXTURE_FILE")"
    mutation_file="$case_workspace/$mutation_file_rel"

    if [[ ! -f "$mutation_file" ]]; then
        printf '[FAIL] %s (%s): mutation file missing: %s\n' "$case_id" "$surface" "$mutation_file_rel"
        mkdir -p "$(dirname "$REPORT_NDJSON")"
        jq -n \
            --arg fixture_id "$case_id" \
            --arg surface "$surface" \
            --arg purpose "$purpose" \
            --arg file "$mutation_file_rel" \
            '{fixture_id:$fixture_id,surface:$surface,purpose:$purpose,status:"failed",reason:"mutation_file_missing",mutation_file:$file,exit_code:null,expected_exit:null,diagnostic_checks:[]}' \
            >> "$REPORT_NDJSON"
        fail_count=$((fail_count + 1))
        continue
    fi

    case "$mutation_op" in
        replace_first)
            find_text="$(jq -r --arg id "$case_id" '.cases[] | select(.fixture_id == $id) | .mutation.find' "$FIXTURE_FILE")"
            replace_text="$(jq -r --arg id "$case_id" '.cases[] | select(.fixture_id == $id) | .mutation.replace' "$FIXTURE_FILE")"
            if ! grep -Fq "$find_text" "$mutation_file"; then
                printf '[FAIL] %s (%s): find token not present in %s\n' "$case_id" "$surface" "$mutation_file_rel"
                mkdir -p "$(dirname "$REPORT_NDJSON")"
                jq -n \
                    --arg fixture_id "$case_id" \
                    --arg surface "$surface" \
                    --arg purpose "$purpose" \
                    --arg file "$mutation_file_rel" \
                    '{fixture_id:$fixture_id,surface:$surface,purpose:$purpose,status:"failed",reason:"find_token_missing",mutation_file:$file,exit_code:null,expected_exit:null,diagnostic_checks:[]}' \
                    >> "$REPORT_NDJSON"
                fail_count=$((fail_count + 1))
                continue
            fi
            FIND_TEXT="$find_text" REPLACE_TEXT="$replace_text" perl -0pi -e 's/\Q$ENV{FIND_TEXT}\E/$ENV{REPLACE_TEXT}/' "$mutation_file"
            ;;
        append_text)
            append_text="$(jq -r --arg id "$case_id" '.cases[] | select(.fixture_id == $id) | .mutation.text' "$FIXTURE_FILE")"
            printf '\n%s\n' "$append_text" >> "$mutation_file"
            ;;
        *)
            printf '[FAIL] %s (%s): unsupported mutation operation: %s\n' "$case_id" "$surface" "$mutation_op"
            mkdir -p "$(dirname "$REPORT_NDJSON")"
            jq -n \
                --arg fixture_id "$case_id" \
                --arg surface "$surface" \
                --arg purpose "$purpose" \
                --arg op "$mutation_op" \
                '{fixture_id:$fixture_id,surface:$surface,purpose:$purpose,status:"failed",reason:"unsupported_mutation_op",mutation_op:$op,exit_code:null,expected_exit:null,diagnostic_checks:[]}' \
                >> "$REPORT_NDJSON"
            fail_count=$((fail_count + 1))
            continue
            ;;
    esac

    command_str="$(jq -r --arg id "$case_id" '.cases[] | select(.fixture_id == $id) | .command' "$FIXTURE_FILE")"
    expected_exit="$(jq -r --arg id "$case_id" '.cases[] | select(.fixture_id == $id) | .expected_exit' "$FIXTURE_FILE")"
    if ! parse_command_args "$command_str"; then
        printf '[FAIL] %s (%s): unsupported fixture command syntax\n' "$case_id" "$surface"
        jq -n \
            --arg fixture_id "$case_id" \
            --arg surface "$surface" \
            --arg purpose "$purpose" \
            --arg command "$command_str" \
            '{fixture_id:$fixture_id,surface:$surface,purpose:$purpose,status:"failed",reason:"unsupported_command_syntax",command:$command,exit_code:null,expected_exit:null,diagnostic_checks:[]}' \
            >> "$REPORT_NDJSON"
        fail_count=$((fail_count + 1))
        continue
    fi

    log_file="$LOG_DIR/${case_id}.log"
    mkdir -p "$(dirname "$log_file")"

    run_with_rch=false
    if [[ "$run_via_rch" == "true" && "$NO_RCH" == "false" ]] && command -v rch >/dev/null 2>&1; then
        run_with_rch=true
    fi

    rc=0
    if [[ "$run_with_rch" == "true" ]]; then
        set +e
        (cd "$case_workspace" && rch exec -- "${COMMAND_ARGS[@]}") >"$log_file" 2>&1
        rc=$?
        set -e
    else
        set +e
        (
            cd "$case_workspace" && \
            env \
                GIT_DIR="$PROJECT_ROOT/.git" \
                GIT_WORK_TREE="$case_workspace" \
                GIT_INDEX_FILE="$case_index" \
                "${COMMAND_ARGS[@]}"
        ) >"$log_file" 2>&1
        rc=$?
        set -e
    fi

    diagnostics_ok=true
    mapfile -t expected_needles < <(jq -r --arg id "$case_id" '.cases[] | select(.fixture_id == $id) | .expected_substrings[]' "$FIXTURE_FILE")
    missing_needles=()
    for needle in "${expected_needles[@]}"; do
        if ! grep -Fq "$needle" "$log_file"; then
            diagnostics_ok=false
            missing_needles+=("$needle")
        fi
    done

    status="passed"
    reason="ok"
    if [[ "$rc" != "$expected_exit" ]]; then
        status="failed"
        reason="unexpected_exit"
    elif [[ "$diagnostics_ok" != "true" ]]; then
        status="failed"
        reason="diagnostic_mismatch"
    fi

    if [[ "$status" == "passed" ]]; then
        printf '[PASS] %s (%s): expected failure observed with actionable diagnostics\n' "$case_id" "$surface"
        pass_count=$((pass_count + 1))
    else
        printf '[FAIL] %s (%s): reason=%s expected_exit=%s actual_exit=%s\n' \
            "$case_id" "$surface" "$reason" "$expected_exit" "$rc"
        if [[ ${#missing_needles[@]} -gt 0 ]]; then
            printf '       missing diagnostics:\n'
            for needle in "${missing_needles[@]}"; do
                printf '         - %s\n' "$needle"
            done
        fi
        fail_count=$((fail_count + 1))
    fi

    missing_json='[]'
    if [[ ${#missing_needles[@]} -gt 0 ]]; then
        missing_json="$(printf '%s\n' "${missing_needles[@]}" | jq -R . | jq -s .)"
    fi

    mkdir -p "$(dirname "$REPORT_NDJSON")"
    jq -n \
        --arg fixture_id "$case_id" \
        --arg surface "$surface" \
        --arg purpose "$purpose" \
        --arg status "$status" \
        --arg reason "$reason" \
        --arg command "$command_str" \
        --arg mutation_op "$mutation_op" \
        --arg mutation_file "$mutation_file_rel" \
        --argjson expected_exit "$expected_exit" \
        --argjson exit_code "$rc" \
        --argjson diagnostics_ok "$diagnostics_ok" \
        --argjson missing_diagnostics "$missing_json" \
        --arg log_file "$log_file" \
        '{
            fixture_id:$fixture_id,
            surface:$surface,
            purpose:$purpose,
            status:$status,
            reason:$reason,
            command:$command,
            mutation:{operation:$mutation_op,file:$mutation_file},
            expected_exit:$expected_exit,
            exit_code:$exit_code,
            diagnostics_ok:$diagnostics_ok,
            missing_diagnostics:$missing_diagnostics,
            log_file:$log_file
        }' >> "$REPORT_NDJSON"
done

status="pass"
if [[ $fail_count -gt 0 ]]; then
    status="fail"
fi

ensure_artifact_dirs
jq -n \
    --arg schema_version "semantic-guardrail-mismatch-report-v1" \
    --arg fixture_schema_version "$SCHEMA_VERSION" \
    --arg run_id "$RUN_ID" \
    --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --argjson light_only "$LIGHT_ONLY" \
    --argjson no_rch "$NO_RCH" \
    --arg status "$status" \
    --arg report_ndjson "$REPORT_NDJSON" \
    --arg logs_dir "$LOG_DIR" \
    --argjson selected_cases "${#CASE_IDS[@]}" \
    --argjson passed "$pass_count" \
    --argjson failed "$fail_count" \
    --argjson skipped "$skip_count" \
    '{
        schema_version:$schema_version,
        fixture_schema_version:$fixture_schema_version,
        run_id:$run_id,
        generated_at:$generated_at,
        light_only:$light_only,
        no_rch:$no_rch,
        status:$status,
        selected_cases:$selected_cases,
        passed:$passed,
        failed:$failed,
        skipped:$skipped,
        report_ndjson:$report_ndjson,
        logs_dir:$logs_dir
    }' > "$REPORT_JSON"

printf '\n=== SEM-10.4 mismatch harness summary ===\n'
printf '  Selected: %s\n' "${#CASE_IDS[@]}"
printf '  Passed:   %s\n' "$pass_count"
printf '  Failed:   %s\n' "$fail_count"
printf '  Skipped:  %s\n' "$skip_count"
printf '  Summary:  %s\n' "$REPORT_JSON"
printf '  Logs:     %s\n' "$LOG_DIR"

if [[ "$status" != "pass" ]]; then
    exit 1
fi
exit 0
