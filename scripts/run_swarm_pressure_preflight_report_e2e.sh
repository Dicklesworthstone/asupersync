#!/usr/bin/env bash
set -euo pipefail

fixture=""
repo_path="$(pwd)"
output_dir="${TMPDIR:-/tmp}/asupersync-swarm-pressure-preflight-e2e-$$"
generated_at=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --fixture)
      fixture="${2:?--fixture requires a path}"
      shift 2
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

if [[ -z "${fixture}" ]]; then
  echo "[swarm-pressure-preflight:e2e] --fixture is required" >&2
  exit 2
fi

mkdir -p "${output_dir}"
receipt_path="${output_dir}/swarm_pressure_preflight_report.json"

cmd=(
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

"${cmd[@]}" > "${receipt_path}"

echo "[swarm-pressure-preflight:e2e] source_artifacts_begin"
jq -r '
  .source_artifacts[]
  | "[swarm-pressure-preflight:e2e] source kind=\(.kind) path=\(.artifact_path // "<inline>") version=\(.version // "<missing>") digest=\(.digest // "<missing>") status=\(.load_status)"
' "${receipt_path}"
echo "[swarm-pressure-preflight:e2e] source_artifacts_end"

jq -r '
  .sections.proof_lane_envelope_health
  | "[swarm-pressure-preflight:e2e] envelope lane_count=\(.lane_count) class_count=\(.resource_envelope_class_count) states=\(.lane_states | tojson) pressure=\(.resource_pressure_counts | tojson)"
' "${receipt_path}"

jq -r '
  .sections.proof_status_snapshot
  | "[swarm-pressure-preflight:e2e] proof_status claims=\(.claim_count) by_status=\(.by_status | tojson) by_evidence=\(.by_proof_evidence_status | tojson)"
' "${receipt_path}"

jq -r '
  .sections.proof_freshness
  | "[swarm-pressure-preflight:e2e] freshness receipts=\(.receipt_count) rows=\(.row_count) classifications=\(.by_classification | tojson) decisions=\(.by_decision | tojson)"
' "${receipt_path}"

jq -r '
  .sections.proof_admission
  | "[swarm-pressure-preflight:e2e] admission receipts=\(.receipt_count) admissible=\(.admissible_count) blocked=\(.blocked_count) decisions=\(.by_decision | tojson)"
' "${receipt_path}"

jq -r '
  .sections.pressure_summary
  | "[swarm-pressure-preflight:e2e] pressure classes=\(.classes | join(",")) mixed=\(.mixed_pressure) by_class=\(.by_class | tojson)"
' "${receipt_path}"

jq -r '
  .sections.dirty_tree
  | "[swarm-pressure-preflight:e2e] dirty_tree present=\(.present) decision=\(.decision) blockers=\(.blocker_count) classifications=\(.by_classification // {} | tojson)"
' "${receipt_path}"

echo "[swarm-pressure-preflight:e2e] blockers_begin"
jq -r '
  .blockers[]
  | "[swarm-pressure-preflight:e2e] blocker kind=\(.kind) source=\(.source_kind) lane=\(.lane_id // "") claim=\(.claim_id // "") path=\(.path // "") reason=\(.reason)"
' "${receipt_path}"
echo "[swarm-pressure-preflight:e2e] blockers_end"

echo "[swarm-pressure-preflight:e2e] warnings_begin"
jq -r '
  .warnings[]
  | "[swarm-pressure-preflight:e2e] warning kind=\(.kind) source=\(.source_kind) lane=\(.lane_id // "") claim=\(.claim_id // "") reason=\(.reason)"
' "${receipt_path}"
echo "[swarm-pressure-preflight:e2e] warnings_end"

jq -r '
  .operator_summary
  | "[swarm-pressure-preflight:e2e] final decision=\(.decision) ready_for_release_gate=\(.ready_for_release_gate) ready_to_dispatch_proof_lanes=\(.ready_to_dispatch_proof_lanes) blockers=\(.blocker_count) warnings=\(.warning_count) sources=\(.source_count)"
' "${receipt_path}"
