#!/usr/bin/env bash
set -euo pipefail

# Schema anchors for contract invariants:
# - massive-swarm-skill-provenance-smoke-bundle-v1
# - massive-swarm-skill-provenance-smoke-run-report-v1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CONTRACT_ARTIFACT="${PROJECT_ROOT}/artifacts/massive_swarm_skill_provenance_v1.json"
OUTPUT_ROOT="${MASSIVE_SWARM_SKILL_PROVENANCE_SMOKE_OUTPUT_DIR:-${PROJECT_ROOT}/target/massive-swarm-skill-provenance-smoke}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RUN_DIR="${OUTPUT_ROOT}/run_${TIMESTAMP}"
LIST_ONLY=0
DRY_RUN=1
SELECTED_SCENARIO=""

usage() {
    cat <<'USAGE'
Usage: ./scripts/run_massive_swarm_skill_provenance_smoke.sh [options]

Options:
  --list                    List scenario IDs and exit
  --scenario <id>           Run one scenario
  --output-root <dir>       Override output root (default: target/massive-swarm-skill-provenance-smoke)
  --dry-run                 Emit manifests without executing validation (default)
  --execute                 Execute validation and assert expected counts/fields
  -h, --help                Show help
USAGE
}

require_tools() {
    if ! command -v jq >/dev/null 2>&1; then
        echo "FATAL: jq is required for massive swarm skill provenance smoke runner" >&2
        exit 1
    fi
    if ! command -v sha256sum >/dev/null 2>&1; then
        echo "FATAL: sha256sum is required for deterministic projection checks" >&2
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

list_scenarios() {
    jq -r '.smoke_scenarios[] | [.scenario_id, .description] | @tsv' "$CONTRACT_ARTIFACT" \
        | while IFS=$'\t' read -r scenario_id description; do
            printf '%-44s %s\n' "$scenario_id" "$description"
        done
}

projection_hash() {
    jq -S '{
        contract_version,
        source_skills,
        objective_requirement_count: (.objective_requirements | length),
        generated_idea_count: (.idea_wizard_phase_ledger.generated_ideas | length),
        top_5_count: (.idea_wizard_phase_ledger.top_5 | length),
        next_10_count: (.idea_wizard_phase_ledger.next_10 | length),
        parked_idea_count: (.idea_wizard_phase_ledger.parked_ideas | length),
        graveyard_primitive_count: (.alien_graveyard_provenance | length),
        galaxy_brain_card_count: (.alien_artifact_compilation.galaxy_brain_cards | length),
        bead_mapping_ids: [.selected_bead_mappings[].bead_id] | sort
    }' "$CONTRACT_ARTIFACT" | sha256sum | awk '{print $1}'
}

missing_mapping_field_count() {
    jq '
      [ .selected_bead_mappings[] as $mapping
        | .required_mapping_fields[] as $field
        | select(($mapping[$field] == null)
                 or (($mapping[$field] | type) == "array" and ($mapping[$field] | length) == 0)
                 or (($mapping[$field] | type) == "string" and ($mapping[$field] | length) == 0))
      ] | length
    ' "$CONTRACT_ARTIFACT"
}

duplicate_bead_id_count() {
    jq '
      [.selected_bead_mappings[].bead_id] as $ids
      | ($ids | unique | length) as $unique
      | ($ids | length) - $unique
    ' "$CONTRACT_ARTIFACT"
}

count_field() {
    local expression="$1"
    jq -r "$expression" "$CONTRACT_ARTIFACT"
}

expected_count() {
    local key="$1"
    jq -r --arg key "$key" '.smoke_scenarios[0].expected_counts[$key]' "$CONTRACT_ARTIFACT"
}

validate_counts() {
    local failures=0

    check_min_or_equal "source_skill_count" "$(count_field '.source_skills | length')" "$(expected_count 'source_skill_count')" "eq" || failures=$((failures + 1))
    check_min_or_equal "objective_requirement_count" "$(count_field '.objective_requirements | length')" "$(expected_count 'objective_requirement_count')" "eq" || failures=$((failures + 1))
    check_min_or_equal "generated_idea_count" "$(count_field '.idea_wizard_phase_ledger.generated_ideas | length')" "$(expected_count 'generated_idea_count')" "eq" || failures=$((failures + 1))
    check_min_or_equal "top_5_count" "$(count_field '.idea_wizard_phase_ledger.top_5 | length')" "$(expected_count 'top_5_count')" "eq" || failures=$((failures + 1))
    check_min_or_equal "next_10_count" "$(count_field '.idea_wizard_phase_ledger.next_10 | length')" "$(expected_count 'next_10_count')" "eq" || failures=$((failures + 1))
    check_min_or_equal "parked_idea_count" "$(count_field '.idea_wizard_phase_ledger.parked_ideas | length')" "$(expected_count 'parked_idea_count')" "eq" || failures=$((failures + 1))
    check_min_or_equal "minimum_bead_mapping_count" "$(count_field '.selected_bead_mappings | length')" "$(expected_count 'minimum_bead_mapping_count')" "min" || failures=$((failures + 1))
    check_min_or_equal "minimum_graveyard_primitive_count" "$(count_field '.alien_graveyard_provenance | length')" "$(expected_count 'minimum_graveyard_primitive_count')" "min" || failures=$((failures + 1))
    check_min_or_equal "minimum_galaxy_brain_card_count" "$(count_field '.alien_artifact_compilation.galaxy_brain_cards | length')" "$(expected_count 'minimum_galaxy_brain_card_count')" "min" || failures=$((failures + 1))

    local missing_fields duplicate_ids
    missing_fields="$(missing_mapping_field_count)"
    duplicate_ids="$(duplicate_bead_id_count)"
    echo "missing_mapping_field_count=${missing_fields}"
    echo "duplicate_bead_id_count=${duplicate_ids}"
    if [[ "$missing_fields" -ne 0 ]]; then
        failures=$((failures + 1))
    fi
    if [[ "$duplicate_ids" -ne 0 ]]; then
        failures=$((failures + 1))
    fi

    return "$failures"
}

check_min_or_equal() {
    local name="$1"
    local actual="$2"
    local expected="$3"
    local mode="$4"
    local ok=0

    if [[ "$mode" == "eq" ]]; then
        [[ "$actual" -eq "$expected" ]] && ok=1
    else
        [[ "$actual" -ge "$expected" ]] && ok=1
    fi

    echo "${name}: actual=${actual} expected_${mode}=${expected}"
    [[ "$ok" -eq 1 ]]
}

run_scenario() {
    local scenario_id="$1"
    local scenario_json
    scenario_json="$(jq -c --arg scenario_id "$scenario_id" '.smoke_scenarios[] | select(.scenario_id == $scenario_id)' "$CONTRACT_ARTIFACT")"
    if [[ -z "$scenario_json" ]]; then
        echo "FATAL: unknown scenario id: ${scenario_id}" >&2
        return 1
    fi

    local scenario_dir="${RUN_DIR}/${scenario_id}"
    local log_file="${scenario_dir}/run.log"
    local bundle_manifest="${scenario_dir}/bundle_manifest.json"
    local run_report="${scenario_dir}/run_report.json"
    local started_ts ended_ts status validation_passed script_exit_code first_hash second_hash missing_fields duplicate_ids

    mkdir -p "$scenario_dir"
    started_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    first_hash="$(projection_hash)"
    second_hash="$(projection_hash)"
    missing_fields="$(missing_mapping_field_count)"
    duplicate_ids="$(duplicate_bead_id_count)"

    {
        echo "scenario_id=${scenario_id}"
        echo "contract_version=$(contract_version)"
        echo "source_repo_hash=$(git -C "$PROJECT_ROOT" rev-parse --short=12 HEAD 2>/dev/null || printf unknown)"
        echo "source_skill_count=$(count_field '.source_skills | length')"
        echo "input_bead_count=$(count_field '.selected_bead_mappings | length')"
        echo "selected_idea_count=$(count_field '.idea_wizard_phase_ledger.top_5 | length')"
        echo "rejected_idea_count=$(count_field '.idea_wizard_phase_ledger.parked_ideas | length')"
        echo "canonical_source_file_count=$(count_field '[.alien_graveyard_provenance[].canonical_source_ref] | unique | length')"
        echo "missing_field_count=${missing_fields}"
        echo "duplicate_bead_id_count=${duplicate_ids}"
        echo "projection_hash_first=${first_hash}"
        echo "projection_hash_second=${second_hash}"
        echo "repeated_run_hash_match=$([[ "$first_hash" == "$second_hash" ]] && printf true || printf false)"
        echo "artifact_path=${CONTRACT_ARTIFACT}"
    } | tee "$log_file" >/dev/null

    validation_passed=false
    script_exit_code=0
    status="dry_run"
    if [[ "$DRY_RUN" -eq 0 ]]; then
        set +e
        validate_counts >>"$log_file" 2>&1
        script_exit_code=$?
        set -e
        if [[ "$script_exit_code" -eq 0 ]] && [[ "$first_hash" == "$second_hash" ]]; then
            validation_passed=true
            status="passed"
        else
            status="failed"
        fi
    fi

    ended_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    cat >"$bundle_manifest" <<JSON
{
  "schema_version": "$(json_escape "$(bundle_schema_version)")",
  "contract_version": "$(json_escape "$(contract_version)")",
  "scenario_id": "$(json_escape "$scenario_id")",
  "artifact_path": "$(json_escape "$bundle_manifest")",
  "run_log_path": "$(json_escape "$log_file")",
  "mode": "$([ "$DRY_RUN" -eq 1 ] && printf dry_run || printf execute)",
  "source_repo_hash": "$(json_escape "$(git -C "$PROJECT_ROOT" rev-parse --short=12 HEAD 2>/dev/null || printf unknown)")",
  "source_skills": $(jq -c '.source_skills' "$CONTRACT_ARTIFACT"),
  "input_bead_count": $(count_field '.selected_bead_mappings | length'),
  "selected_idea_count": $(count_field '.idea_wizard_phase_ledger.top_5 | length'),
  "rejected_idea_count": $(count_field '.idea_wizard_phase_ledger.parked_ideas | length'),
  "missing_field_count": ${missing_fields},
  "duplicate_bead_id_count": ${duplicate_ids},
  "canonical_source_references": $(jq -c '[.alien_graveyard_provenance[].canonical_source_ref] | unique | sort' "$CONTRACT_ARTIFACT"),
  "projection_hash": "$(json_escape "$first_hash")",
  "repeated_run_hash_match": $( [[ "$first_hash" == "$second_hash" ]] && printf true || printf false ),
  "validation_passed": ${validation_passed},
  "status": "$(json_escape "$status")",
  "started_ts": "$(json_escape "$started_ts")",
  "ended_ts": "$(json_escape "$ended_ts")"
}
JSON

    cat >"$run_report" <<JSON
{
  "schema_version": "$(json_escape "$(report_schema_version)")",
  "contract_version": "$(json_escape "$(contract_version)")",
  "artifact_path": "$(json_escape "$run_report")",
  "bundle_manifest_path": "$(json_escape "$bundle_manifest")",
  "run_log_path": "$(json_escape "$log_file")",
  "run_dir": "$(json_escape "$RUN_DIR")",
  "scenario_id": "$(json_escape "$scenario_id")",
  "mode": "$([ "$DRY_RUN" -eq 1 ] && printf dry_run || printf execute)",
  "script_exit_code": ${script_exit_code},
  "validation_passed": ${validation_passed},
  "status": "$(json_escape "$status")",
  "message": "$([ "$status" == "passed" ] && printf "skill provenance artifact is complete for signoff ingestion" || printf "skill provenance artifact was not executed or failed validation")",
  "source_repo_hash": "$(json_escape "$(git -C "$PROJECT_ROOT" rev-parse --short=12 HEAD 2>/dev/null || printf unknown)")",
  "source_skills": $(jq -c '.source_skills' "$CONTRACT_ARTIFACT"),
  "input_bead_count": $(count_field '.selected_bead_mappings | length'),
  "selected_idea_count": $(count_field '.idea_wizard_phase_ledger.top_5 | length'),
  "rejected_idea_count": $(count_field '.idea_wizard_phase_ledger.parked_ideas | length'),
  "missing_field_count": ${missing_fields},
  "duplicate_bead_id_count": ${duplicate_ids},
  "generated_artifact_paths": [
    "$(json_escape "$bundle_manifest")",
    "$(json_escape "$run_report")",
    "$(json_escape "$log_file")"
  ],
  "repeated_run_hash_match": $( [[ "$first_hash" == "$second_hash" ]] && printf true || printf false ),
  "projection_hash": "$(json_escape "$first_hash")"
}
JSON

    echo ""
    echo "==================================================================="
    echo "        MASSIVE SWARM SKILL PROVENANCE SMOKE SUMMARY              "
    echo "==================================================================="
    echo "  Run dir:   ${RUN_DIR}"
    echo "  Report:    ${run_report}"
    echo "  Mode:      $([ "$DRY_RUN" -eq 1 ] && printf "DRY-RUN" || printf "EXECUTE")"
    echo "  Status:    $(printf '%s' "$status" | tr '[:lower:]' '[:upper:]')"
    echo "==================================================================="

    [[ "$status" != "failed" ]]
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --list)
            LIST_ONLY=1
            shift
            ;;
        --scenario)
            SELECTED_SCENARIO="${2:-}"
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
    list_scenarios
    exit 0
fi

if [[ -z "$SELECTED_SCENARIO" ]]; then
    SELECTED_SCENARIO="$(jq -r '.smoke_scenarios[0].scenario_id' "$CONTRACT_ARTIFACT")"
fi

mkdir -p "$RUN_DIR"
run_scenario "$SELECTED_SCENARIO"
