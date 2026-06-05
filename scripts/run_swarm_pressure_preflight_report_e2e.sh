#!/usr/bin/env bash
set -euo pipefail

fixtures=()
suite=false
repo_path="$(pwd)"
output_dir="${TMPDIR:-/tmp}/asupersync-swarm-pressure-preflight-e2e-$$"
generated_at=""

default_suite_fixtures=(
  "tests/fixtures/swarm_pressure_preflight_report/green.json"
  "tests/fixtures/swarm_pressure_preflight_report/stale_exact_filter.json"
  "tests/fixtures/swarm_pressure_preflight_report/missing_envelope.json"
  "tests/fixtures/swarm_pressure_preflight_report/local_fallback_attempt.json"
  "tests/fixtures/swarm_pressure_preflight_report/peer_dirty_tree.json"
  "tests/fixtures/swarm_pressure_preflight_report/chaos_pressure.json"
  "tests/fixtures/swarm_pressure_preflight_report/blocked.json"
)

while [[ $# -gt 0 ]]; do
  case "$1" in
    --fixture)
      fixtures+=("${2:?--fixture requires a path}")
      shift 2
      ;;
    --suite)
      suite=true
      shift
      ;;
    --repo-path)
      repo_path="${2:?--repo-path requires a path}"
      shift 2
      ;;
    --output-dir)
      output_dir="${2:?--output-dir requires a path}"
      shift 2
      ;;
    --generated-at)
      generated_at="${2:?--generated-at requires a timestamp}"
      shift 2
      ;;
    *)
      echo "[swarm-pressure-preflight:e2e] unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ "${suite}" == true && "${#fixtures[@]}" -eq 0 ]]; then
  for default_fixture in "${default_suite_fixtures[@]}"; do
    fixtures+=("${repo_path}/${default_fixture}")
  done
fi

if [[ "${#fixtures[@]}" -eq 0 ]]; then
  echo "[swarm-pressure-preflight:e2e] --fixture or --suite is required" >&2
  exit 2
fi

mkdir -p "${output_dir}"
case_rows_path="${output_dir}/cases.ndjson"
suite_summary_path="${output_dir}/swarm_pressure_preflight_e2e_summary.json"
: > "${case_rows_path}"

run_case() {
  local fixture="$1"
  local case_output_dir="$2"
  local receipt_path="${case_output_dir}/swarm_pressure_preflight_report.json"
  mkdir -p "${case_output_dir}"

  local cmd=(
    python3
    "${repo_path}/scripts/swarm_pressure_preflight_report.py"
    --fixture "${fixture}"
    --repo-path "${repo_path}"
    --output json
  )

  if [[ -n "${generated_at}" ]]; then
    cmd+=(--generated-at "${generated_at}")
  fi

  echo "[swarm-pressure-preflight:e2e] repo_path=${repo_path}"
  echo "[swarm-pressure-preflight:e2e] fixture=${fixture}"
  echo "[swarm-pressure-preflight:e2e] output=${receipt_path}"
  echo "[swarm-pressure-preflight:e2e] command=${cmd[*]}"

  if ! "${cmd[@]}" > "${receipt_path}"; then
    echo "[swarm-pressure-preflight:e2e] case_failed_to_generate fixture=${fixture}" >&2
    return 1
  fi

  local case_id expected_decision actual_decision expected_blockers actual_blockers expected_warnings actual_warnings case_status
  case_id="$(jq -r '.e2e_expectations.case_id // .profile_id' "${receipt_path}")"
  expected_decision="$(jq -r '.e2e_expectations.expected_decision // ""' "${receipt_path}")"
  actual_decision="$(jq -r '.operator_summary.decision' "${receipt_path}")"
  expected_blockers="$(jq -c '.e2e_expectations.expected_blocker_kinds // []' "${receipt_path}")"
  actual_blockers="$(jq -c '[.blockers[].kind] | sort' "${receipt_path}")"
  expected_warnings="$(jq -c '.e2e_expectations.expected_warning_kinds // []' "${receipt_path}")"
  actual_warnings="$(jq -c '[.warnings[].kind] | sort' "${receipt_path}")"

  case_status="unchecked"
  if [[ -n "${expected_decision}" ]]; then
    case_status="pass"
    if [[ "${expected_decision}" != "${actual_decision}" ]] \
      || [[ "${expected_blockers}" != "${actual_blockers}" ]] \
      || [[ "${expected_warnings}" != "${actual_warnings}" ]]; then
      case_status="fail"
    fi
  fi

  echo "[swarm-pressure-preflight:e2e] case_begin id=${case_id} fixture=${fixture}"
  echo "[swarm-pressure-preflight:e2e] source_artifacts_begin case=${case_id}"
  jq -r --arg case_id "${case_id}" '
    .source_artifacts[]
    | "[swarm-pressure-preflight:e2e] case=\($case_id) source kind=\(.kind) path=\(.artifact_path // "<inline>") version=\(.version // "<missing>") digest=\(.digest // "<missing>") status=\(.load_status)"
  ' "${receipt_path}"
  echo "[swarm-pressure-preflight:e2e] source_artifacts_end case=${case_id}"

  jq -r --arg case_id "${case_id}" '
    .sections.proof_lane_envelope_health
    | "[swarm-pressure-preflight:e2e] case=\($case_id) envelope lane_count=\(.lane_count) class_count=\(.resource_envelope_class_count) states=\(.lane_states | tojson) pressure=\(.resource_pressure_counts | tojson)"
  ' "${receipt_path}"

  echo "[swarm-pressure-preflight:e2e] commands_begin case=${case_id}"
  jq -r --arg case_id "${case_id}" '
    .sections.proof_lane_envelope_health.lanes[]
    | "[swarm-pressure-preflight:e2e] case=\($case_id) command lane=\(.lane_id) kind=\(.kind) command=\(.command)"
  ' "${receipt_path}"
  echo "[swarm-pressure-preflight:e2e] commands_end case=${case_id}"

  echo "[swarm-pressure-preflight:e2e] envelopes_begin case=${case_id}"
  jq -r --arg case_id "${case_id}" '
    .sections.proof_lane_envelope_health.lanes[]
    | .resource_envelope as $env
    | "[swarm-pressure-preflight:e2e] case=\($case_id) envelope_values lane=\(.lane_id) class=\(.resource_envelope_class) timeout_seconds=\($env.timeout_seconds // 0) memory_mb=\($env.memory_mb // 0) remote_required=\($env.remote_required // false) local_fallback_allowed=\($env.local_fallback_allowed // false) resource_pressure=\($env.resource_pressure // "unknown") state=\(.state)"
  ' "${receipt_path}"
  echo "[swarm-pressure-preflight:e2e] envelopes_end case=${case_id}"

  jq -r --arg case_id "${case_id}" '
    .sections.proof_status_snapshot
    | "[swarm-pressure-preflight:e2e] case=\($case_id) proof_status claims=\(.claim_count) by_status=\(.by_status | tojson) by_evidence=\(.by_proof_evidence_status | tojson)"
  ' "${receipt_path}"

  jq -r --arg case_id "${case_id}" '
    .sections.proof_freshness
    | "[swarm-pressure-preflight:e2e] case=\($case_id) freshness receipts=\(.receipt_count) rows=\(.row_count) classifications=\(.by_classification | tojson) decisions=\(.by_decision | tojson)"
  ' "${receipt_path}"

  echo "[swarm-pressure-preflight:e2e] parsed_test_counts_begin case=${case_id}"
  jq -r --arg case_id "${case_id}" '
    .sections.proof_freshness.rows[]
    | "[swarm-pressure-preflight:e2e] case=\($case_id) parsed_tests lane=\(.lane_id) exact_filter=\(.exact_filter // "") executed=\(.exact_filter_executed_tests)"
  ' "${receipt_path}"
  echo "[swarm-pressure-preflight:e2e] parsed_test_counts_end case=${case_id}"

  jq -r --arg case_id "${case_id}" '
    .sections.proof_admission
    | "[swarm-pressure-preflight:e2e] case=\($case_id) admission receipts=\(.receipt_count) admissible=\(.admissible_count) blocked=\(.blocked_count) decisions=\(.by_decision | tojson)"
  ' "${receipt_path}"

  jq -r --arg case_id "${case_id}" '
    .sections.pressure_summary
    | "[swarm-pressure-preflight:e2e] case=\($case_id) pressure classes=\(.classes | join(",")) mixed=\(.mixed_pressure) by_class=\(.by_class | tojson)"
  ' "${receipt_path}"

  jq -r --arg case_id "${case_id}" '
    .sections.dirty_tree
    | "[swarm-pressure-preflight:e2e] case=\($case_id) dirty_tree present=\(.present) decision=\(.decision) blockers=\(.blocker_count) classifications=\(.by_classification // {} | tojson)"
  ' "${receipt_path}"

  echo "[swarm-pressure-preflight:e2e] dirty_classifications_begin case=${case_id}"
  jq -r --arg case_id "${case_id}" '
    .sections.dirty_tree.rows[]
    | "[swarm-pressure-preflight:e2e] case=\($case_id) dirty_path path=\(.path) classification=\(.classification) owner=\(.owner) release_blocker=\(.release_blocker) reason=\(.reason)"
  ' "${receipt_path}"
  echo "[swarm-pressure-preflight:e2e] dirty_classifications_end case=${case_id}"

  echo "[swarm-pressure-preflight:e2e] blockers_begin case=${case_id}"
  jq -r --arg case_id "${case_id}" '
    .blockers[]
    | "[swarm-pressure-preflight:e2e] case=\($case_id) blocker kind=\(.kind) source=\(.source_kind) lane=\(.lane_id // "") claim=\(.claim_id // "") path=\(.path // "") reason=\(.reason)"
  ' "${receipt_path}"
  echo "[swarm-pressure-preflight:e2e] blockers_end case=${case_id}"

  echo "[swarm-pressure-preflight:e2e] warnings_begin case=${case_id}"
  jq -r --arg case_id "${case_id}" '
    .warnings[]
    | "[swarm-pressure-preflight:e2e] case=\($case_id) warning kind=\(.kind) source=\(.source_kind) lane=\(.lane_id // "") claim=\(.claim_id // "") reason=\(.reason)"
  ' "${receipt_path}"
  echo "[swarm-pressure-preflight:e2e] warnings_end case=${case_id}"

  jq -r --arg case_id "${case_id}" '
    .operator_summary
    | "[swarm-pressure-preflight:e2e] case=\($case_id) final decision=\(.decision) ready_for_release_gate=\(.ready_for_release_gate) ready_to_dispatch_proof_lanes=\(.ready_to_dispatch_proof_lanes) blockers=\(.blocker_count) warnings=\(.warning_count) sources=\(.source_count)"
  ' "${receipt_path}"

  local final_blocker_list
  final_blocker_list="$(jq -c '[.blockers[] | {kind, source_kind, lane_id, claim_id, path, reason}]' "${receipt_path}")"
  echo "[swarm-pressure-preflight:e2e] case=${case_id} expectation expected_decision=${expected_decision:-<unspecified>} actual_decision=${actual_decision} expected_blockers=${expected_blockers} actual_blockers=${actual_blockers} expected_warnings=${expected_warnings} actual_warnings=${actual_warnings}"
  echo "[swarm-pressure-preflight:e2e] case=${case_id} final_blocker_list=${final_blocker_list}"
  echo "[swarm-pressure-preflight:e2e] case_end id=${case_id} status=${case_status}"

  jq -n \
    --arg case_id "${case_id}" \
    --arg fixture "${fixture}" \
    --arg receipt_path "${receipt_path}" \
    --arg generated_at "$(jq -r '.generated_at' "${receipt_path}")" \
    --arg expected_decision "${expected_decision}" \
    --arg actual_decision "${actual_decision}" \
    --arg status "${case_status}" \
    --argjson expected_blockers "${expected_blockers}" \
    --argjson actual_blockers "${actual_blockers}" \
    --argjson expected_warnings "${expected_warnings}" \
    --argjson actual_warnings "${actual_warnings}" \
    '{
      case_id: $case_id,
      fixture: $fixture,
      receipt_path: $receipt_path,
      generated_at: $generated_at,
      expected_decision: $expected_decision,
      actual_decision: $actual_decision,
      expected_blocker_kinds: $expected_blockers,
      actual_blocker_kinds: $actual_blockers,
      expected_warning_kinds: $expected_warnings,
      actual_warning_kinds: $actual_warnings,
      status: $status
    }' >> "${case_rows_path}"

  [[ "${case_status}" != "fail" ]]
}

overall_status=0
single_case=false
if [[ "${suite}" == false && "${#fixtures[@]}" -eq 1 ]]; then
  single_case=true
fi

for fixture in "${fixtures[@]}"; do
  case_name="$(basename "${fixture}" .json)"
  case_output_dir="${output_dir}/${case_name}"
  if [[ "${single_case}" == true ]]; then
    case_output_dir="${output_dir}"
  fi
  if ! run_case "${fixture}" "${case_output_dir}"; then
    overall_status=1
  fi
done

jq -s \
  '{
    schema_version: "swarm-pressure-preflight-e2e-summary-v1",
    case_count: length,
    pass_count: map(select(.status == "pass")) | length,
    fail_count: map(select(.status == "fail")) | length,
    unchecked_count: map(select(.status == "unchecked")) | length,
    cases: .
  }' "${case_rows_path}" > "${suite_summary_path}"

echo "[swarm-pressure-preflight:e2e] suite_summary=${suite_summary_path}"
jq -r '
  "[swarm-pressure-preflight:e2e] suite case_count=\(.case_count) pass_count=\(.pass_count) fail_count=\(.fail_count) unchecked_count=\(.unchecked_count)"
' "${suite_summary_path}"

exit "${overall_status}"
