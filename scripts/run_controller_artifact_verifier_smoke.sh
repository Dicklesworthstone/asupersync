#!/usr/bin/env bash
set -euo pipefail

# Schema anchors for contract invariants:
# - controller-artifact-verifier-smoke-bundle-v1
# - controller-artifact-verifier-smoke-run-report-v1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CONTRACT_ARTIFACT="${PROJECT_ROOT}/artifacts/controller_artifact_contract_v1.json"
OUTPUT_ROOT="${CONTROLLER_ARTIFACT_SMOKE_OUTPUT_DIR:-${PROJECT_ROOT}/target/controller-artifact-smoke}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RUN_DIR="${OUTPUT_ROOT}/run_${TIMESTAMP}"
LIST_ONLY=0
DRY_RUN=1

declare -a SELECTED_CASES=()

usage() {
    cat <<'USAGE'
Usage: ./scripts/run_controller_artifact_verifier_smoke.sh [options]

Options:
  --list                    List case IDs and exit
  --case <id>               Run one case (repeatable)
  --output-root <dir>       Override output root (default: target/controller-artifact-smoke)
  --dry-run                 Emit manifests without executing verifier (default)
  --execute                 Execute verifier and assert expected verdicts
  -h, --help                Show help
USAGE
}

require_tools() {
    if ! command -v jq >/dev/null 2>&1; then
        echo "FATAL: jq is required for controller artifact smoke runner" >&2
        exit 1
    fi
    if [ ! -f "$CONTRACT_ARTIFACT" ]; then
        echo "FATAL: contract artifact missing at ${CONTRACT_ARTIFACT}" >&2
        exit 1
    fi
}

json_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

contract_version() {
    jq -r '.contract_version' "$CONTRACT_ARTIFACT"
}

bundle_schema_version() {
    jq -r '.runner_bundle_schema_version' "$CONTRACT_ARTIFACT"
}

report_schema_version() {
    jq -r '.runner_report_schema_version' "$CONTRACT_ARTIFACT"
}

list_cases() {
    jq -r '.verification_cases[] | [.case_id, .intent, .expect_verdict] | @tsv' "$CONTRACT_ARTIFACT" \
        | while IFS=$'\t' read -r case_id intent expect_verdict; do
            printf '%-38s expect=%-24s %s\n' "$case_id" "$expect_verdict" "$intent"
        done
}

load_case_json() {
    local case_id="$1"
    jq -c --arg case_id "$case_id" '.verification_cases[] | select(.case_id == $case_id)' "$CONTRACT_ARTIFACT"
}

append_result() {
    local entry="$1"
    if [[ -z "${RESULTS_JSON:-}" ]]; then
        RESULTS_JSON="$entry"
    else
        RESULTS_JSON="${RESULTS_JSON},${entry}"
    fi
}

verify_manifest() {
    local case_json="$1"
    local manifest
    manifest="$(jq -c '.manifest' <<<"$case_json")"

    local verdict="accept"
    local rejection_code="none"
    local rejection_reason="accepted"

    while IFS= read -r field; do
        if ! jq -e --arg field "$field" '.[$field] != null' <<<"$manifest" >/dev/null; then
            verdict="reject_missing_field"
            rejection_code="missing_field:${field}"
            rejection_reason="required manifest field missing"
            echo "${verdict}|${rejection_code}|${rejection_reason}"
            return 0
        fi
    done < <(jq -r '.required_manifest_fields[]' "$CONTRACT_ARTIFACT")

    while IFS= read -r field; do
        if ! jq -e --arg field "$field" '.fallback[$field] != null' <<<"$manifest" >/dev/null; then
            verdict="reject_missing_field"
            rejection_code="missing_field:fallback.${field}"
            rejection_reason="required fallback field missing"
            echo "${verdict}|${rejection_code}|${rejection_reason}"
            return 0
        fi
    done < <(jq -r '.required_fallback_fields[]' "$CONTRACT_ARTIFACT")

    while IFS= read -r field; do
        if ! jq -e --arg field "$field" '.integrity[$field] != null' <<<"$manifest" >/dev/null; then
            verdict="reject_missing_field"
            rejection_code="missing_field:integrity.${field}"
            rejection_reason="required integrity field missing"
            echo "${verdict}|${rejection_code}|${rejection_reason}"
            return 0
        fi
    done < <(jq -r '.required_integrity_fields[]' "$CONTRACT_ARTIFACT")

    local manifest_schema_version
    manifest_schema_version="$(jq -r '.manifest_schema_version // ""' <<<"$manifest")"
    if [[ "$manifest_schema_version" != "controller-artifact-manifest-v1" ]]; then
        echo "reject_schema_mismatch|schema:manifest_version|unsupported manifest schema"
        return 0
    fi

    local runtime_major runtime_minor min_major min_minor max_major max_minor
    runtime_major="$(jq -r '.runtime_snapshot_version.major' "$CONTRACT_ARTIFACT")"
    runtime_minor="$(jq -r '.runtime_snapshot_version.minor' "$CONTRACT_ARTIFACT")"
    min_major="$(jq -r '.snapshot_version_range.min.major' <<<"$manifest")"
    min_minor="$(jq -r '.snapshot_version_range.min.minor' <<<"$manifest")"
    max_major="$(jq -r '.snapshot_version_range.max.major' <<<"$manifest")"
    max_minor="$(jq -r '.snapshot_version_range.max.minor' <<<"$manifest")"

    if (( runtime_major < min_major )) || (( runtime_major > max_major )); then
        echo "reject_version_mismatch|compatibility:snapshot_version|runtime major outside controller range"
        return 0
    fi

    if (( runtime_major == min_major )) && (( runtime_minor < min_minor )); then
        echo "reject_version_mismatch|compatibility:snapshot_version|runtime minor below controller minimum"
        return 0
    fi

    if (( runtime_major == max_major )) && (( runtime_minor > max_minor )); then
        echo "reject_version_mismatch|compatibility:snapshot_version|runtime minor above controller maximum"
        return 0
    fi

    local hash_ok sig_ok
    hash_ok="$(jq -r '.integrity.hash_chain.valid // false' <<<"$manifest")"
    sig_ok="$(jq -r '.integrity.signature_chain.valid // false' <<<"$manifest")"

    if [[ "$hash_ok" != "true" ]]; then
        echo "reject_hash_mismatch|integrity:hash_chain|hash chain validation failed"
        return 0
    fi

    if [[ "$sig_ok" != "true" ]]; then
        echo "reject_signature_mismatch|integrity:signature_chain|signature chain validation failed"
        return 0
    fi

    echo "accept|none|accepted"
}

run_case() {
    local case_id="$1"
    local case_json
    case_json="$(load_case_json "$case_id")"
    if [[ -z "$case_json" ]]; then
        echo "FATAL: unknown case id: ${case_id}" >&2
        return 1
    fi

    local intent expect_verdict expect_rejection_code
    intent="$(jq -r '.intent' <<<"$case_json")"
    expect_verdict="$(jq -r '.expect_verdict' <<<"$case_json")"
    expect_rejection_code="$(jq -r '.expect_rejection_code' <<<"$case_json")"

    local case_dir="${RUN_DIR}/${case_id}"
    local log_file="${case_dir}/run.log"
    local summary_file="${case_dir}/bundle_manifest.json"
    local started_ts ended_ts status rc actual_verdict actual_rejection_code actual_rejection_reason

    mkdir -p "$case_dir"
    started_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    echo ">>> Running case ${case_id}"
    echo "    intent: ${intent}"
    echo "    expected: ${expect_verdict} (${expect_rejection_code})"

    if [[ "$DRY_RUN" -eq 1 ]]; then
        printf 'DRY_RUN verifier_case=%s\n' "$case_id" | tee "$log_file" >/dev/null
        actual_verdict="not_executed"
        actual_rejection_code="none"
        actual_rejection_reason="dry_run"
        rc=0
        status="dry_run"
    else
        local verdict_tuple
        verdict_tuple="$(verify_manifest "$case_json")"
        IFS='|' read -r actual_verdict actual_rejection_code actual_rejection_reason <<<"$verdict_tuple"

        {
            echo "case_id=${case_id}"
            echo "actual_verdict=${actual_verdict}"
            echo "actual_rejection_code=${actual_rejection_code}"
            echo "actual_rejection_reason=${actual_rejection_reason}"
            echo "expected_verdict=${expect_verdict}"
            echo "expected_rejection_code=${expect_rejection_code}"
        } | tee "$log_file" >/dev/null

        rc=0
        status="passed"
        if [[ "$actual_verdict" != "$expect_verdict" ]] || [[ "$actual_rejection_code" != "$expect_rejection_code" ]]; then
            rc=1
            status="failed"
        fi
    fi

    ended_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    cat >"$summary_file" <<JSON
{
  "schema_version": "$(json_escape "$(bundle_schema_version)")",
  "contract_version": "$(json_escape "$(contract_version)")",
  "case_id": "$(json_escape "$case_id")",
  "intent": "$(json_escape "$intent")",
  "expected_verdict": "$(json_escape "$expect_verdict")",
  "expected_rejection_code": "$(json_escape "$expect_rejection_code")",
  "actual_verdict": "$(json_escape "$actual_verdict")",
  "actual_rejection_code": "$(json_escape "$actual_rejection_code")",
  "actual_rejection_reason": "$(json_escape "$actual_rejection_reason")",
  "artifact_path": "$(json_escape "$summary_file")",
  "run_log_path": "$(json_escape "$log_file")",
  "status": "$(json_escape "$status")",
  "exit_code": ${rc},
  "started_ts": "$(json_escape "$started_ts")",
  "ended_ts": "$(json_escape "$ended_ts")"
}
JSON

    append_result "$(jq -c '.' "$summary_file")"

    [[ "$rc" -eq 0 ]]
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --list)
            LIST_ONLY=1
            shift
            ;;
        --case)
            SELECTED_CASES+=("${2:-}")
            shift 2
            ;;
        --output-root)
            OUTPUT_ROOT="${2:-}"
            RUN_DIR="${OUTPUT_ROOT}/run_${TIMESTAMP}"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        --execute)
            DRY_RUN=0
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

require_tools

if [[ "$LIST_ONLY" -eq 1 ]]; then
    list_cases
    exit 0
fi

if [[ "${#SELECTED_CASES[@]}" -eq 0 ]]; then
    mapfile -t SELECTED_CASES < <(jq -r '.verification_cases[].case_id' "$CONTRACT_ARTIFACT")
fi

mkdir -p "$RUN_DIR"
RESULTS_JSON=""
OVERALL_RC=0

for case_id in "${SELECTED_CASES[@]}"; do
    if ! run_case "$case_id"; then
        OVERALL_RC=1
    fi
done

RUN_REPORT="${RUN_DIR}/run_report.json"
cat >"$RUN_REPORT" <<JSON
{
  "schema_version": "$(json_escape "$(report_schema_version)")",
  "contract_version": "$(json_escape "$(contract_version)")",
  "artifact_path": "$(json_escape "$RUN_REPORT")",
  "run_dir": "$(json_escape "$RUN_DIR")",
  "selected_cases": $(jq -nc --argjson ids "$(printf '%s\n' "${SELECTED_CASES[@]}" | jq -Rsc 'split("\n") | map(select(length > 0))')" '$ids'),
  "dry_run": $( [[ "$DRY_RUN" -eq 1 ]] && printf 'true' || printf 'false' ),
  "results": [${RESULTS_JSON}],
  "status": "$([ "$OVERALL_RC" -eq 0 ] && printf "passed" || printf "failed")"
}
JSON

echo ""
echo "==================================================================="
echo "            CONTROLLER ARTIFACT VERIFIER SMOKE SUMMARY           "
echo "==================================================================="
echo "  Run dir:   ${RUN_DIR}"
echo "  Report:    ${RUN_REPORT}"
echo "  Mode:      $([ "$DRY_RUN" -eq 1 ] && printf "DRY-RUN" || printf "EXECUTE")"
echo "  Status:    $([ "$OVERALL_RC" -eq 0 ] && printf "PASSED" || printf "FAILED")"
echo "==================================================================="

exit "$OVERALL_RC"
