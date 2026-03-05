#!/usr/bin/env bash
# Doctor Full-Stack Reference Projects E2E Runner (asupersync-2b4jj.6.5)
#
# Validates deterministic full workflow regression coverage for three
# reference-project complexity profiles:
# - small
# - medium
# - large
#
# For each selected profile, this suite:
# 1. Executes all profile stages twice (run1 + run2) through existing
#    doctor E2E scripts that route heavy cargo work through rch.
# 2. Captures per-stage structured diagnostics and artifact pointers.
# 3. Verifies deterministic cross-run stability for profile outcome state.
# 4. Emits a final `e2e-suite-summary-v3` report with repro commands.
#
# Usage:
#   ./scripts/test_doctor_full_stack_reference_projects_e2e.sh
#
# Environment:
#   PROFILE_MODE      all|small|medium|large (default: all)
#   TEST_SEED         base deterministic seed (default: 4242)
#   RCH_BIN           rch executable (default: ~/.local/bin/rch)
#   PROFILE_TIMEOUT   per-stage timeout seconds (default: 1200)
#   RUN_RETRIES       retries per stage (default: 2)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RUN_STARTED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
OUTPUT_DIR="${PROJECT_ROOT}/target/e2e-results/doctor_full_stack_reference_projects"
STAGING_ROOT="$(mktemp -d "/tmp/asupersync-doctor-fullstack-${TIMESTAMP}-XXXXXX")"
ARTIFACT_DIR="${STAGING_ROOT}/artifacts_${TIMESTAMP}"
PUBLISHED_ARTIFACT_DIR="${OUTPUT_DIR}/artifacts_${TIMESTAMP}"
SUMMARY_FILE="${PUBLISHED_ARTIFACT_DIR}/summary.json"
RUN1_REPORT="${ARTIFACT_DIR}/run1.json"
RUN2_REPORT="${ARTIFACT_DIR}/run2.json"
RUN1_NORM="${ARTIFACT_DIR}/run1.normalized.json"
RUN2_NORM="${ARTIFACT_DIR}/run2.normalized.json"
RUN_DIFF="${ARTIFACT_DIR}/run_determinism.diff"
PROFILE_MODE="${PROFILE_MODE:-all}"
BASE_SEED="${TEST_SEED:-4242}"
PROFILE_TIMEOUT="${PROFILE_TIMEOUT:-1200}"
RUN_RETRIES="${RUN_RETRIES:-2}"
MAX_DIAGNOSIS_TIME_DELTA_PCT="${MAX_DIAGNOSIS_TIME_DELTA_PCT:-25}"
MAX_FALSE_POSITIVE_RATE_PCT="${MAX_FALSE_POSITIVE_RATE_PCT:-5}"
MAX_FALSE_NEGATIVE_RATE_PCT="${MAX_FALSE_NEGATIVE_RATE_PCT:-5}"
MIN_REMEDIATION_SUCCESS_RATE_PCT="${MIN_REMEDIATION_SUCCESS_RATE_PCT:-95}"
MIN_OPERATOR_CONFIDENCE_SCORE="${MIN_OPERATOR_CONFIDENCE_SCORE:-80}"
QUALITY_GATE_2B4JJ_6_6_STATUS="${QUALITY_GATE_2B4JJ_6_6_STATUS:-external}"
QUALITY_GATE_2B4JJ_6_7_STATUS="${QUALITY_GATE_2B4JJ_6_7_STATUS:-external}"
QUALITY_GATE_2B4JJ_6_8_STATUS="${QUALITY_GATE_2B4JJ_6_8_STATUS:-external}"

SUITE_ID="doctor_full_stack_reference_projects_e2e"
SCENARIO_ID="E2E-SUITE-DOCTOR-FULLSTACK-REFERENCE-PROJECTS"

RCH_BIN="${RCH_BIN:-$HOME/.local/bin/rch}"
if [[ ! -x "${RCH_BIN}" ]]; then
    echo "FATAL: rch is required and was not found/executable at: ${RCH_BIN}" >&2
    exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "FATAL: jq is required for report synthesis" >&2
    exit 1
fi

normalize_quality_gate_status() {
    local value
    value="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
    case "${value}" in
        green | yellow | red | unknown | external)
            printf '%s\n' "${value}"
            ;;
        *)
            echo "FATAL: invalid quality-gate status '${1}' (allowed: green|yellow|red|unknown|external)" >&2
            exit 1
            ;;
    esac
}

QUALITY_GATE_2B4JJ_6_6_STATUS="$(normalize_quality_gate_status "${QUALITY_GATE_2B4JJ_6_6_STATUS}")"
QUALITY_GATE_2B4JJ_6_7_STATUS="$(normalize_quality_gate_status "${QUALITY_GATE_2B4JJ_6_7_STATUS}")"
QUALITY_GATE_2B4JJ_6_8_STATUS="$(normalize_quality_gate_status "${QUALITY_GATE_2B4JJ_6_8_STATUS}")"

mkdir -p "${ARTIFACT_DIR}" "${PUBLISHED_ARTIFACT_DIR}"

declare -a SELECTED_PROFILES=()

select_profiles() {
    case "${PROFILE_MODE}" in
        all)
            SELECTED_PROFILES=("small" "medium" "large")
            ;;
        small | medium | large)
            SELECTED_PROFILES=("${PROFILE_MODE}")
            ;;
        *)
            echo "FATAL: PROFILE_MODE must be one of: all|small|medium|large (got '${PROFILE_MODE}')" >&2
            exit 1
            ;;
    esac
}

profile_scripts() {
    local profile_id="$1"
    case "${profile_id}" in
        small)
            cat <<'EOF'
scripts/test_doctor_workspace_scan_e2e.sh
scripts/test_doctor_invariant_analyzer_e2e.sh
EOF
            ;;
        medium)
            cat <<'EOF'
scripts/test_doctor_orchestration_state_machine_e2e.sh
scripts/test_doctor_scenario_coverage_packs_e2e.sh
EOF
            ;;
        large)
            cat <<'EOF'
scripts/test_doctor_remediation_verification_e2e.sh
scripts/test_doctor_remediation_failure_injection_e2e.sh
scripts/test_doctor_report_export_e2e.sh
EOF
            ;;
        *)
            return 1
            ;;
    esac
}

classify_failure() {
    local stage_id="$1"
    local exit_code="$2"

    if [[ "${exit_code}" -eq 124 ]]; then
        printf '%s\n' "timeout"
        return 0
    fi

    case "${stage_id}" in
        *workspace_scan*)
            printf '%s\n' "workspace_scan_failure"
            ;;
        *invariant_analyzer*)
            printf '%s\n' "invariant_analyzer_failure"
            ;;
        *orchestration_state_machine* | *scenario_coverage_packs*)
            printf '%s\n' "orchestration_failure"
            ;;
        *remediation* | *report_export*)
            printf '%s\n' "remediation_or_reporting_failure"
            ;;
        *)
            printf '%s\n' "unknown_failure"
            ;;
    esac
}

derive_profile_seed() {
    local profile_id="$1"
    printf '%s:%s\n' "${BASE_SEED}" "${profile_id}"
}

run_stage_script() {
    local profile_id="$1"
    local run_label="$2"
    local script_rel="$3"
    local stage_dir="$4"
    local profile_seed="$5"

    mkdir -p "${stage_dir}"

    local stage_id
    stage_id="$(basename "${script_rel}" .sh)"
    local stage_log="${stage_dir}/${stage_id}.log"
    local stage_json="${stage_dir}/${stage_id}.json"
    local attempt_log="${stage_dir}/${stage_id}.attempt.log"
    local exit_code=1
    local summary_path=""
    local summary_status="missing"

    for ((attempt = 1; attempt <= RUN_RETRIES; attempt++)); do
        : > "${attempt_log}"
        local stage_started_ts
        stage_started_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        pushd "${PROJECT_ROOT}" >/dev/null
        set +e
        DOCTOR_FULLSTACK_SINGLE_RUN=1 \
            TEST_SEED="${profile_seed}" \
            timeout "${PROFILE_TIMEOUT}s" \
            bash "${PROJECT_ROOT}/${script_rel}" >"${attempt_log}" 2>&1
        exit_code=$?
        set -e
        popd >/dev/null
        local stage_ended_ts
        stage_ended_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

        cp "${attempt_log}" "${stage_log}"
        summary_path="$(
            grep -E 'Summary:' "${stage_log}" | tail -n1 | sed -E 's/.*Summary:[[:space:]]*//' || true
        )"
        if [[ -n "${summary_path}" && -f "${summary_path}" ]]; then
            summary_status="$(jq -r '.status // "missing"' "${summary_path}" 2>/dev/null || echo "missing")"
        else
            summary_status="missing"
        fi

        if [[ "${exit_code}" -eq 0 ]]; then
            jq -n \
                --arg profile_id "${profile_id}" \
                --arg run_id "${run_label}" \
                --arg stage_id "${stage_id}" \
                --arg script "${script_rel}" \
                --arg started_ts "${stage_started_ts}" \
                --arg ended_ts "${stage_ended_ts}" \
                --arg status "passed" \
                --arg summary_path "${summary_path}" \
                --arg summary_status "${summary_status}" \
                --arg repro_command "PROFILE_MODE=${profile_id} TEST_SEED=${profile_seed} RCH_BIN=${RCH_BIN} bash ${SCRIPT_DIR}/$(basename "$0")" \
                '{
                    profile_id: $profile_id,
                    run_id: $run_id,
                    stage_id: $stage_id,
                    script: $script,
                    started_ts: $started_ts,
                    ended_ts: $ended_ts,
                    status: $status,
                    summary_path: $summary_path,
                    summary_status: $summary_status,
                    failure_class: "none",
                    exit_code: 0,
                    log_file: "",
                    repro_command: $repro_command
                }' >"${stage_json}"
            jq --arg log_file "${stage_log}" '.log_file = $log_file' "${stage_json}" >"${stage_json}.tmp"
            mv "${stage_json}.tmp" "${stage_json}"
            printf '%s\n' "${stage_json}"
            return 0
        fi
    done

    local final_started_ts
    final_started_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    local failure_class
    failure_class="$(classify_failure "${stage_id}" "${exit_code}")"
    jq -n \
        --arg profile_id "${profile_id}" \
        --arg run_id "${run_label}" \
        --arg stage_id "${stage_id}" \
        --arg script "${script_rel}" \
        --arg started_ts "${final_started_ts}" \
        --arg ended_ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --arg status "failed" \
        --arg summary_path "${summary_path}" \
        --arg summary_status "${summary_status}" \
        --arg failure_class "${failure_class}" \
        --arg log_file "${stage_log}" \
        --arg repro_command "PROFILE_MODE=${profile_id} TEST_SEED=${profile_seed} RCH_BIN=${RCH_BIN} bash ${SCRIPT_DIR}/$(basename "$0")" \
        --argjson exit_code "${exit_code}" \
        '{
            profile_id: $profile_id,
            run_id: $run_id,
            stage_id: $stage_id,
            script: $script,
            started_ts: $started_ts,
            ended_ts: $ended_ts,
            status: $status,
            summary_path: $summary_path,
            summary_status: $summary_status,
            failure_class: $failure_class,
            exit_code: $exit_code,
            log_file: $log_file,
            repro_command: $repro_command
        }' >"${stage_json}"
    printf '%s\n' "${stage_json}"
    return 1
}

run_profile() {
    local run_label="$1"
    local profile_id="$2"
    local run_root="$3"
    local profile_seed="$4"

    local profile_dir="${run_root}/${profile_id}"
    mkdir -p "${profile_dir}"
    local stage_records=()
    local profile_status="passed"

    mapfile -t scripts_for_profile < <(profile_scripts "${profile_id}")
    if [[ "${#scripts_for_profile[@]}" -eq 0 ]]; then
        echo "FATAL: no scripts defined for profile ${profile_id}" >&2
        return 1
    fi

    for script_rel in "${scripts_for_profile[@]}"; do
        local stage_record
        if stage_record="$(run_stage_script "${profile_id}" "${run_label}" "${script_rel}" "${profile_dir}" "${profile_seed}")"; then
            stage_records+=("${stage_record}")
        else
            stage_records+=("${stage_record}")
            profile_status="failed"
        fi
    done

    local profile_report="${profile_dir}/profile_report.json"
    jq -s \
        --arg profile_id "${profile_id}" \
        --arg run_id "${run_label}" \
        --arg profile_seed "${profile_seed}" \
        --arg status "${profile_status}" \
        --arg repro_command "PROFILE_MODE=${profile_id} TEST_SEED=${BASE_SEED} RCH_BIN=${RCH_BIN} bash ${SCRIPT_DIR}/$(basename "$0")" \
        '{
            profile_id: $profile_id,
            run_id: $run_id,
            profile_seed: $profile_seed,
            status: $status,
            repro_command: $repro_command,
            stages: .,
            failed_stage_ids: [ .[] | select(.status != "passed") | .stage_id ],
            failure_classes: [ .[] | select(.status != "passed") | .failure_class ] | unique
        }' "${stage_records[@]}" >"${profile_report}"

    printf '%s\n' "${profile_report}"
    return 0
}

run_suite_iteration() {
    local run_label="$1"
    local run_report="$2"
    local run_root="${ARTIFACT_DIR}/${run_label}"
    mkdir -p "${run_root}"
    local profile_reports=()

    for profile_id in "${SELECTED_PROFILES[@]}"; do
        local profile_seed
        profile_seed="$(derive_profile_seed "${profile_id}")"
        local profile_report
        profile_report="$(run_profile "${run_label}" "${profile_id}" "${run_root}" "${profile_seed}")"
        profile_reports+=("${profile_report}")
    done

    jq -s \
        --arg run_id "${run_label}" \
        --arg generated_ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        '{
            run_id: $run_id,
            generated_ts: $generated_ts,
            profiles: .,
            status_by_profile: (map({key: .profile_id, value: .status}) | from_entries)
        }' "${profile_reports[@]}" >"${run_report}"
}

select_profiles

echo "==================================================================="
echo " Asupersync Doctor Full-Stack Reference Projects E2E              "
echo "==================================================================="
echo "Config:"
echo "  RCH_BIN:           ${RCH_BIN}"
echo "  PROFILE_MODE:      ${PROFILE_MODE}"
echo "  TEST_SEED(base):   ${BASE_SEED}"
echo "  PROFILE_TIMEOUT:   ${PROFILE_TIMEOUT}"
echo "  RUN_RETRIES:       ${RUN_RETRIES}"
echo "  MAX_DIAG_DELTA%:   ${MAX_DIAGNOSIS_TIME_DELTA_PCT}"
echo "  MAX_FALSE_POS%:    ${MAX_FALSE_POSITIVE_RATE_PCT}"
echo "  MAX_FALSE_NEG%:    ${MAX_FALSE_NEGATIVE_RATE_PCT}"
echo "  MIN_REMEDIATION%:  ${MIN_REMEDIATION_SUCCESS_RATE_PCT}"
echo "  MIN_CONFIDENCE:    ${MIN_OPERATOR_CONFIDENCE_SCORE}"
echo "  QG 2b4jj.6.6:      ${QUALITY_GATE_2B4JJ_6_6_STATUS}"
echo "  QG 2b4jj.6.7:      ${QUALITY_GATE_2B4JJ_6_7_STATUS}"
echo "  QG 2b4jj.6.8:      ${QUALITY_GATE_2B4JJ_6_8_STATUS}"
echo "  Artifact staging:  ${ARTIFACT_DIR}"
echo "  Artifact output:   ${PUBLISHED_ARTIFACT_DIR}"
echo "  Profiles:          ${SELECTED_PROFILES[*]}"
echo ""

EXIT_CODE=0
CHECK_FAILURES=0
CHECKS_PASSED=0
METRIC_GATE_FAILURES=0
QUALITY_GATE_FAILURES=0
DETERMINISM_FAILURES=0
ROLLOUT_GATE_STATUS="green"
ROLLOUT_DECISION="continue"

echo ">>> [1/4] Running full-stack profile matrix (run1)..."
run_suite_iteration "run1" "${RUN1_REPORT}"

echo ">>> [2/4] Running full-stack profile matrix (run2)..."
run_suite_iteration "run2" "${RUN2_REPORT}"

echo ">>> [3/5] Verifying deterministic cross-run profile outcomes..."
jq -S '[.profiles[] | {profile_id, status, failed_stage_ids}] | sort_by(.profile_id)' "${RUN1_REPORT}" >"${RUN1_NORM}"
jq -S '[.profiles[] | {profile_id, status, failed_stage_ids}] | sort_by(.profile_id)' "${RUN2_REPORT}" >"${RUN2_NORM}"
if diff -u "${RUN1_NORM}" "${RUN2_NORM}" >"${RUN_DIFF}"; then
    CHECKS_PASSED=$((CHECKS_PASSED + 1))
    rm -f "${RUN_DIFF}"
else
    echo "  ERROR: run1/run2 profile outcomes diverged (see ${RUN_DIFF})"
    CHECK_FAILURES=$((CHECK_FAILURES + 1))
    DETERMINISM_FAILURES=1
fi

echo ">>> [4/5] Building final profile report summary..."
FINAL_REPORT_JSON="${ARTIFACT_DIR}/profiles.final.json"
jq -n \
    --slurpfile run2 "${RUN2_REPORT}" \
    '{
        profiles: ($run2[0].profiles // []),
        failed_profiles: (($run2[0].profiles // []) | map(select(.status != "passed"))),
        pass_count: (($run2[0].profiles // []) | map(select(.status == "passed")) | length),
        fail_count: (($run2[0].profiles // []) | map(select(.status != "passed")) | length)
    }' >"${FINAL_REPORT_JSON}"

FAILED_PROFILE_COUNT="$(jq -r '.fail_count' "${FINAL_REPORT_JSON}")"
if [[ "${FAILED_PROFILE_COUNT}" -gt 0 ]]; then
    CHECK_FAILURES=$((CHECK_FAILURES + FAILED_PROFILE_COUNT))
fi

echo ">>> [5/5] Computing dogfood rollout adoption metrics..."
ADOPTION_METRICS_FILE="${ARTIFACT_DIR}/adoption_metrics.json"
jq -n \
    --slurpfile run1 "${RUN1_REPORT}" \
    --slurpfile run2 "${RUN2_REPORT}" \
    '
    def round3: ((. * 1000) | round) / 1000;
    def absval: if . < 0 then -. else . end;
    def stage_pairs($run):
        [
            $run.profiles[]? as $profile
            | $profile.stages[]?
            | {
                key: ($profile.profile_id + "::" + .stage_id),
                profile_id: $profile.profile_id,
                stage_id: .stage_id,
                status: .status,
                duration_seconds: (((.ended_ts | fromdateiso8601) - (.started_ts | fromdateiso8601)) | if . < 0 then 0 else . end)
            }
        ];
    def stage_map($pairs):
        reduce $pairs[] as $item ({}; .[$item.key] = $item);
    def diagnosis_seconds($run):
        ([ $run.profiles[]? | select(.profile_id == "small") | .stages[]?
           | (((.ended_ts | fromdateiso8601) - (.started_ts | fromdateiso8601)) | if . < 0 then 0 else . end)
         ] | add) // 0;
    def remediation_stats($run):
        ([ $run.profiles[]?
           | select(.profile_id == "large")
           | .stages[]?
           | select(.stage_id | test("remediation|report_export"))
         ]) as $stages
        | {
            total: ($stages | length),
            passed: ($stages | map(select(.status == "passed")) | length)
          };

    $run1[0] as $r1
    | $run2[0] as $r2
    | stage_pairs($r1) as $pairs1
    | stage_pairs($r2) as $pairs2
    | stage_map($pairs1) as $map1
    | stage_map($pairs2) as $map2
    | ([ $pairs1[].key, $pairs2[].key ] | unique) as $keys
    | ($keys | length) as $total_pairs
    | ([ $keys[]
         | select((($map1[.]?.status) // "missing") != "passed" and (($map2[.]?.status) // "missing") == "passed")
       ] | length) as $false_positive_pairs
    | ([ $keys[]
         | select((($map1[.]?.status) // "missing") == "passed" and (($map2[.]?.status) // "missing") != "passed")
       ] | length) as $false_negative_pairs
    | ([ $keys[]
         | select((($map1[.]?.status) // "missing") == (($map2[.]?.status) // "missing"))
       ] | length) as $deterministic_pairs
    | diagnosis_seconds($r1) as $diagnosis_run1_seconds
    | diagnosis_seconds($r2) as $diagnosis_run2_seconds
    | (if $diagnosis_run1_seconds <= 0
       then 0
       else (($diagnosis_run2_seconds - $diagnosis_run1_seconds) / $diagnosis_run1_seconds) * 100
       end) as $diagnosis_time_delta_pct
    | remediation_stats($r2) as $remediation
    | (if $total_pairs == 0 then 0 else ($false_positive_pairs / $total_pairs) * 100 end) as $false_positive_rate_pct
    | (if $total_pairs == 0 then 0 else ($false_negative_pairs / $total_pairs) * 100 end) as $false_negative_rate_pct
    | (if $remediation.total == 0 then 0 else ($remediation.passed / $remediation.total) * 100 end) as $remediation_success_rate_pct
    | (if $total_pairs == 0 then 0 else ($deterministic_pairs / $total_pairs) * 100 end) as $deterministic_pair_rate_pct
    | (
        100
        - (($diagnosis_time_delta_pct | absval) * 1.5)
        - ($false_positive_rate_pct * 3.0)
        - ($false_negative_rate_pct * 3.0)
        - ((100 - $remediation_success_rate_pct) * 0.5)
        - ((100 - $deterministic_pair_rate_pct) * 0.5)
      ) as $raw_confidence
    | ($raw_confidence | if . < 0 then 0 elif . > 100 then 100 else . end) as $operator_confidence_score
    | {
        diagnosis_run1_seconds: ($diagnosis_run1_seconds | round3),
        diagnosis_run2_seconds: ($diagnosis_run2_seconds | round3),
        diagnosis_time_delta_pct: ($diagnosis_time_delta_pct | round3),
        false_positive_pairs: $false_positive_pairs,
        false_negative_pairs: $false_negative_pairs,
        total_stage_pairs: $total_pairs,
        false_positive_rate_pct: ($false_positive_rate_pct | round3),
        false_negative_rate_pct: ($false_negative_rate_pct | round3),
        remediation_stage_count: $remediation.total,
        remediation_passed_count: $remediation.passed,
        remediation_success_rate_pct: ($remediation_success_rate_pct | round3),
        deterministic_pair_rate_pct: ($deterministic_pair_rate_pct | round3),
        operator_confidence_score: ($operator_confidence_score | round3),
        confidence_formula: "100 - |diagnosis_delta_pct|*1.5 - fp_rate*3 - fn_rate*3 - (100-remediation_success_rate)*0.5 - (100-deterministic_pair_rate)*0.5",
        metric_sources: {
            diagnosis_profile: "small",
            remediation_profile: "large",
            pairing_key: "profile_id::stage_id"
        }
      }' >"${ADOPTION_METRICS_FILE}"

if ! jq -e --argjson max "${MAX_DIAGNOSIS_TIME_DELTA_PCT}" \
    '((.diagnosis_time_delta_pct | if . < 0 then -. else . end) <= $max)' \
    "${ADOPTION_METRICS_FILE}" >/dev/null; then
    CHECK_FAILURES=$((CHECK_FAILURES + 1))
    METRIC_GATE_FAILURES=$((METRIC_GATE_FAILURES + 1))
fi

if ! jq -e --argjson max "${MAX_FALSE_POSITIVE_RATE_PCT}" \
    '(.false_positive_rate_pct <= $max)' \
    "${ADOPTION_METRICS_FILE}" >/dev/null; then
    CHECK_FAILURES=$((CHECK_FAILURES + 1))
    METRIC_GATE_FAILURES=$((METRIC_GATE_FAILURES + 1))
fi

if ! jq -e --argjson max "${MAX_FALSE_NEGATIVE_RATE_PCT}" \
    '(.false_negative_rate_pct <= $max)' \
    "${ADOPTION_METRICS_FILE}" >/dev/null; then
    CHECK_FAILURES=$((CHECK_FAILURES + 1))
    METRIC_GATE_FAILURES=$((METRIC_GATE_FAILURES + 1))
fi

if ! jq -e --argjson min "${MIN_REMEDIATION_SUCCESS_RATE_PCT}" \
    '(.remediation_success_rate_pct >= $min)' \
    "${ADOPTION_METRICS_FILE}" >/dev/null; then
    CHECK_FAILURES=$((CHECK_FAILURES + 1))
    METRIC_GATE_FAILURES=$((METRIC_GATE_FAILURES + 1))
fi

if ! jq -e --argjson min "${MIN_OPERATOR_CONFIDENCE_SCORE}" \
    '(.operator_confidence_score >= $min)' \
    "${ADOPTION_METRICS_FILE}" >/dev/null; then
    CHECK_FAILURES=$((CHECK_FAILURES + 1))
    METRIC_GATE_FAILURES=$((METRIC_GATE_FAILURES + 1))
fi

if [[ "${METRIC_GATE_FAILURES}" -gt 0 ]]; then
    ROLLOUT_GATE_STATUS="blocked"
    ROLLOUT_DECISION="hold"
fi

QUALITY_GATES_FILE="${ARTIFACT_DIR}/quality_gate_dependencies.json"
jq -n \
    --arg s66 "${QUALITY_GATE_2B4JJ_6_6_STATUS}" \
    --arg s67 "${QUALITY_GATE_2B4JJ_6_7_STATUS}" \
    --arg s68 "${QUALITY_GATE_2B4JJ_6_8_STATUS}" \
    '[
        {id: "asupersync-2b4jj.6.6", status: $s66},
        {id: "asupersync-2b4jj.6.7", status: $s67},
        {id: "asupersync-2b4jj.6.8", status: $s68}
    ]' >"${QUALITY_GATES_FILE}"

QUALITY_GATE_FAILURES="$(jq '[.[] | select(.status != "green")] | length' "${QUALITY_GATES_FILE}")"
if [[ "${QUALITY_GATE_FAILURES}" -gt 0 ]]; then
    CHECK_FAILURES=$((CHECK_FAILURES + QUALITY_GATE_FAILURES))
    ROLLOUT_GATE_STATUS="blocked"
    ROLLOUT_DECISION="hold"
fi

RUN_ENDED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
SUITE_STATUS="failed"
FAILURE_CLASS="profile_or_determinism_failure"
if [[ "${CHECK_FAILURES}" -eq 0 ]]; then
    SUITE_STATUS="passed"
    FAILURE_CLASS="none"
elif [[ "${QUALITY_GATE_FAILURES}" -gt 0 && "${FAILED_PROFILE_COUNT}" -eq 0 && "${DETERMINISM_FAILURES}" -eq 0 && "${METRIC_GATE_FAILURES}" -eq 0 ]]; then
    FAILURE_CLASS="quality_gate_dependency_failure"
elif [[ "${METRIC_GATE_FAILURES}" -gt 0 && "${FAILED_PROFILE_COUNT}" -eq 0 && "${DETERMINISM_FAILURES}" -eq 0 ]]; then
    FAILURE_CLASS="rollout_gate_failure"
fi

jq -n \
    --arg schema_version "e2e-suite-summary-v3" \
    --arg suite_id "${SUITE_ID}" \
    --arg scenario_id "${SCENARIO_ID}" \
    --arg seed "${BASE_SEED}" \
    --arg started_ts "${RUN_STARTED_TS}" \
    --arg ended_ts "${RUN_ENDED_TS}" \
    --arg status "${SUITE_STATUS}" \
    --arg failure_class "${FAILURE_CLASS}" \
    --arg repro_command "PROFILE_MODE=${PROFILE_MODE} TEST_SEED=${BASE_SEED} RCH_BIN=${RCH_BIN} bash ${SCRIPT_DIR}/$(basename "$0")" \
    --arg artifact_path "${SUMMARY_FILE}" \
    --arg suite "${SUITE_ID}" \
    --arg timestamp "${TIMESTAMP}" \
    --arg test_log_level "${TEST_LOG_LEVEL:-info}" \
    --arg run1_report "${PUBLISHED_ARTIFACT_DIR}/run1.json" \
    --arg run2_report "${PUBLISHED_ARTIFACT_DIR}/run2.json" \
    --arg final_report "${PUBLISHED_ARTIFACT_DIR}/profiles.final.json" \
    --arg artifact_dir "${PUBLISHED_ARTIFACT_DIR}" \
    --arg rollout_gate_status "${ROLLOUT_GATE_STATUS}" \
    --arg rollout_decision "${ROLLOUT_DECISION}" \
    --argjson max_diagnosis_time_delta_pct "${MAX_DIAGNOSIS_TIME_DELTA_PCT}" \
    --argjson max_false_positive_rate_pct "${MAX_FALSE_POSITIVE_RATE_PCT}" \
    --argjson max_false_negative_rate_pct "${MAX_FALSE_NEGATIVE_RATE_PCT}" \
    --argjson min_remediation_success_rate_pct "${MIN_REMEDIATION_SUCCESS_RATE_PCT}" \
    --argjson min_operator_confidence_score "${MIN_OPERATOR_CONFIDENCE_SCORE}" \
    --argjson checks_passed "${CHECKS_PASSED}" \
    --argjson pattern_failures "${CHECK_FAILURES}" \
    --argjson metric_gate_failures "${METRIC_GATE_FAILURES}" \
    --argjson quality_gate_failures "${QUALITY_GATE_FAILURES}" \
    --slurpfile final "${FINAL_REPORT_JSON}" \
    --slurpfile metrics "${ADOPTION_METRICS_FILE}" \
    --slurpfile quality_gates "${QUALITY_GATES_FILE}" \
    '{
        schema_version: $schema_version,
        suite_id: $suite_id,
        scenario_id: $scenario_id,
        seed: $seed,
        started_ts: $started_ts,
        ended_ts: $ended_ts,
        status: $status,
        failure_class: $failure_class,
        repro_command: $repro_command,
        artifact_path: $artifact_path,
        suite: $suite,
        timestamp: $timestamp,
        test_log_level: $test_log_level,
        run1_report: $run1_report,
        run2_report: $run2_report,
        final_report: $final_report,
        checks_passed: $checks_passed,
        metric_gate_failures: $metric_gate_failures,
        quality_gate_failures: $quality_gate_failures,
        pattern_failures: $pattern_failures,
        profiles_passed: ($final[0].pass_count // 0),
        profiles_failed: ($final[0].fail_count // 0),
        failed_profiles: (($final[0].failed_profiles // []) | map({
            profile_id,
            failure_classes,
            failed_stage_ids,
            repro_command
        })),
        rollout_gate_status: $rollout_gate_status,
        rollout_decision: $rollout_decision,
        adoption_metrics: ($metrics[0] // {}),
        adoption_metric_thresholds: {
            max_diagnosis_time_delta_pct: $max_diagnosis_time_delta_pct,
            max_false_positive_rate_pct: $max_false_positive_rate_pct,
            max_false_negative_rate_pct: $max_false_negative_rate_pct,
            min_remediation_success_rate_pct: $min_remediation_success_rate_pct,
            min_operator_confidence_score: $min_operator_confidence_score
        },
        operator_confidence_signals: {
            deterministic_pair_rate_pct: (($metrics[0].deterministic_pair_rate_pct) // 0),
            remediation_success_rate_pct: (($metrics[0].remediation_success_rate_pct) // 0),
            false_positive_rate_pct: (($metrics[0].false_positive_rate_pct) // 0),
            false_negative_rate_pct: (($metrics[0].false_negative_rate_pct) // 0),
            diagnosis_time_delta_pct: (($metrics[0].diagnosis_time_delta_pct) // 0)
        },
        quality_gate_dependencies: ($quality_gates[0] // []),
        followup_actions: (
            [
                (if $quality_gate_failures > 0
                    then "Resolve prerequisite quality gate statuses (2b4jj.6.6/6.7/6.8) to green before rollout decision can advance"
                    else empty
                 end),
                (if $metric_gate_failures > 0
                    then "Resolve metric threshold breaches before rollout decision can advance"
                    else empty
                 end),
                (if ($quality_gate_failures > 0 or $metric_gate_failures > 0)
                    then "Rerun full-stack profile matrix after remediation with the same seed for replayability"
                    else empty
                 end)
            ] | map(select(type == "string" and length > 0))
        ),
        artifact_links: {
            run1_report: $run1_report,
            run2_report: $run2_report,
            final_report: $final_report,
            quality_gate_dependencies: ($artifact_dir + "/quality_gate_dependencies.json")
        },
        artifact_dir: $artifact_dir
    }' >"${ARTIFACT_DIR}/summary.json"

cp "${RUN1_REPORT}" "${PUBLISHED_ARTIFACT_DIR}/run1.json"
cp "${RUN2_REPORT}" "${PUBLISHED_ARTIFACT_DIR}/run2.json"
cp "${FINAL_REPORT_JSON}" "${PUBLISHED_ARTIFACT_DIR}/profiles.final.json"
cp "${QUALITY_GATES_FILE}" "${PUBLISHED_ARTIFACT_DIR}/quality_gate_dependencies.json"
cp "${ARTIFACT_DIR}/summary.json" "${SUMMARY_FILE}"

echo ""
echo "==================================================================="
echo "  Doctor Full-Stack Reference Projects E2E Summary               "
echo "==================================================================="
echo "  Status:          ${SUITE_STATUS}"
echo "  Check failures:  ${CHECK_FAILURES}"
echo "  Checks passed:   ${CHECKS_PASSED}"
echo "  Summary:         ${SUMMARY_FILE}"
echo "==================================================================="

if [[ "${SUITE_STATUS}" != "passed" ]]; then
    EXIT_CODE=1
fi

exit "${EXIT_CODE}"
