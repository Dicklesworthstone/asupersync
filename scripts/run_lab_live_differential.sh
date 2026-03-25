#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
LOCAL_BIN="${ROOT_DIR}/target/debug/asupersync"
RCH_BIN="${RCH_BIN:-$HOME/.local/bin/rch}"

default_cargo_target_dir() {
  local profile_component
  profile_component="$(sanitize_component "${profile:-adhoc}")"
  printf '%s\n' "${ROOT_DIR}/target/lab-live-differential-cli/${profile_component}-pid-$$"
}

extract_flag_value() {
  local needle="$1"
  shift
  local found=1
  local last_value=""

  while (($#)); do
    case "$1" in
      "${needle}")
        last_value="${2-}"
        found=0
        if (($# >= 2)); then
          shift 2
        else
          shift
        fi
        ;;
      --profile|--seed|--seed-count|--seed-stride|--rotation-date|--out-dir|--scenario)
        if (($# >= 2)); then
          shift 2
        else
          shift
        fi
        ;;
      *)
        shift
        ;;
    esac
  done

  if [[ "${found}" -eq 0 ]]; then
    printf '%s\n' "${last_value}"
    return 0
  fi

  return 1
}

flag_present() {
  local needle="$1"
  shift

  while (($#)); do
    case "$1" in
      "${needle}")
        return 0
        ;;
      --profile|--seed|--seed-count|--seed-stride|--rotation-date|--out-dir|--scenario)
        if (($# >= 2)); then
          shift 2
        else
          shift
        fi
        ;;
      *)
        shift
        ;;
    esac
  done

  return 1
}

report_remote_out_dir_error() {
  local requested_out_dir="$1"
  local json_requested="$2"
  local resolved_requested_out_dir
  local detail

  resolved_requested_out_dir="$(resolve_out_dir "${requested_out_dir}")"
  detail="rch-backed differential runs require --out-dir to stay inside the repository so artifacts can sync back from the worker"

  if [[ "${json_requested}" -eq 1 ]]; then
    jq -nc \
      --arg type "artifact_output_error" \
      --arg title "Unsupported remote artifact output path" \
      --arg detail "${detail}" \
      --arg path "${requested_out_dir}" \
      --arg resolved_path "${resolved_requested_out_dir}" \
      --arg repo_root "${ROOT_DIR}" \
      --arg hint "use a repo-relative path such as target/... or artifacts/... or an absolute path under the repository root" \
      '{
        type: $type,
        title: $title,
        detail: $detail,
        context: {
          path: $path,
          resolved_path: $resolved_path,
          repo_root: $repo_root,
          hint: $hint
        },
        exit_code: 2
      }'
    return
  fi

  {
    echo "Unsupported remote artifact output path"
    echo "${detail}"
    echo "Requested path: ${requested_out_dir}"
    echo "Resolved path: ${resolved_requested_out_dir}"
    echo "Repository root: ${ROOT_DIR}"
    echo "Hint: use a repo-relative path such as target/... or artifacts/... or an absolute path under the repository root"
  } >&2
}

validate_remote_out_dir() {
  local requested_out_dir="$1"
  local json_requested="$2"
  local resolved_requested_out_dir

  resolved_requested_out_dir="$(resolve_out_dir "${requested_out_dir}")"
  if [[ "${resolved_requested_out_dir}" == "${ROOT_DIR}" || "${resolved_requested_out_dir}" == "${ROOT_DIR}/"* ]]; then
    return 0
  fi

  report_remote_out_dir_error "${requested_out_dir}" "${json_requested}"
  return 2
}

run_differential() {
  local cargo_incremental="${CARGO_INCREMENTAL:-0}"
  local cargo_target_dir="${ASUPERSYNC_LAB_DIFFERENTIAL_CARGO_TARGET_DIR:-$(default_cargo_target_dir)}"
  local requested_out_dir="target/e2e-results/lab_live_differential"
  local json_requested=0
  local extracted_out_dir

  if extracted_out_dir="$(extract_flag_value "--out-dir" "$@")"; then
    requested_out_dir="${extracted_out_dir}"
  fi
  if flag_present "--json" "$@"; then
    json_requested=1
  fi

  if [[ -x "${LOCAL_BIN}" ]]; then
    "${LOCAL_BIN}" lab differential "$@"
    return
  fi

  cd "${ROOT_DIR}"
  if [[ -x "${RCH_BIN}" ]]; then
    validate_remote_out_dir "${requested_out_dir}" "${json_requested}" || return $?
    "${RCH_BIN}" exec -- env CARGO_INCREMENTAL="${cargo_incremental}" CARGO_TARGET_DIR="${cargo_target_dir}" cargo run --features cli --bin asupersync -- lab differential "$@"
    return
  fi

  CARGO_INCREMENTAL="${cargo_incremental}" CARGO_TARGET_DIR="${cargo_target_dir}" \
    cargo run --features cli --bin asupersync -- lab differential "$@"
}

resolve_out_dir() {
  local raw="$1"
  if [[ "${raw}" = /* ]]; then
    printf '%s\n' "${raw}"
  else
    printf '%s\n' "${ROOT_DIR}/${raw}"
  fi
}

rotation_index_for_date() {
  python3 - "$1" <<'PY'
from datetime import date
import sys

rotation_date = date.fromisoformat(sys.argv[1])
epoch = date(2026, 1, 1)
print((rotation_date - epoch).days)
PY
}

sanitize_component() {
  printf '%s' "$1" | tr -c 'A-Za-z0-9_-' '_'
}

json_array_from_args() {
  if (($# == 0)); then
    printf '[]'
    return
  fi

  printf '%s\n' "$@" | jq -Rsc 'split("\n")[:-1]'
}

print_nightly_stress_help() {
  cat <<'EOF'
Nightly differential stress wrapper (`asupersync-2a6k9.8.2`)

Usage:
  scripts/run_lab_live_differential.sh --profile nightly-stress [OPTIONS]

Options:
  --seed N             Root seed for deterministic seed rotation (default: 424242)
  --seed-count N       Number of rotated seeds to execute (default: 4)
  --seed-stride N      Distance between derived seeds (default: 9973)
  --rotation-date DATE UTC rotation date in YYYY-MM-DD (default: today)
  --out-dir PATH       Output root (default: target/e2e-results/lab_live_differential)
  --json               Print nightly_stress_manifest.json to stdout

The wrapper runs the admitted `phase1-core` differential pack once per derived
seed, writes each per-seed runner bundle under:

  <out-dir>/nightly-stress/<date>/<seed>/phase1-core/

and emits:

  nightly_stress_manifest.json
  nightly_stress_summary.txt
  retained_divergence_artifacts/
EOF
}

profile=""
root_seed=424242
seed_count=4
seed_stride=9973
rotation_date=""
out_dir="target/e2e-results/lab_live_differential"
json_mode=0
scenario_requested=0
nightly_flags_used=0
show_help=0
pass_through=()

while (($#)); do
  case "$1" in
    --profile)
      profile="${2:?missing value for --profile}"
      pass_through+=("$1" "$2")
      shift 2
      ;;
    --seed)
      root_seed="${2:?missing value for --seed}"
      pass_through+=("$1" "$2")
      shift 2
      ;;
    --seed-count)
      seed_count="${2:?missing value for --seed-count}"
      nightly_flags_used=1
      shift 2
      ;;
    --seed-stride)
      seed_stride="${2:?missing value for --seed-stride}"
      nightly_flags_used=1
      shift 2
      ;;
    --rotation-date)
      rotation_date="${2:?missing value for --rotation-date}"
      nightly_flags_used=1
      shift 2
      ;;
    --out-dir)
      out_dir="${2:?missing value for --out-dir}"
      pass_through+=("$1" "$2")
      shift 2
      ;;
    --scenario)
      scenario_requested=1
      pass_through+=("$1" "$2")
      shift 2
      ;;
    --json)
      json_mode=1
      pass_through+=("$1")
      shift
      ;;
    --help|-h)
      show_help=1
      pass_through+=("$1")
      shift
      ;;
    *)
      pass_through+=("$1")
      shift
      ;;
  esac
done

if [[ "${profile}" != "nightly-stress" ]]; then
  if [[ "${nightly_flags_used}" -eq 1 ]]; then
    echo "nightly-stress-only flags require --profile nightly-stress" >&2
    exit 2
  fi
  run_differential "${pass_through[@]}"
  exit $?
fi

if [[ "${show_help}" -eq 1 ]]; then
  print_nightly_stress_help
  exit 0
fi

if [[ "${scenario_requested}" -eq 1 ]]; then
  echo "nightly-stress does not accept --scenario; it always runs the admitted phase1-core pack" >&2
  exit 2
fi

for numeric in "${root_seed}" "${seed_count}" "${seed_stride}"; do
  if [[ ! "${numeric}" =~ ^[0-9]+$ ]]; then
    echo "nightly-stress requires numeric seed parameters; got '${numeric}'" >&2
    exit 2
  fi
done

if [[ "${seed_count}" -lt 1 ]]; then
  echo "--seed-count must be >= 1" >&2
  exit 2
fi

if [[ "${seed_stride}" -lt 1 ]]; then
  echo "--seed-stride must be >= 1" >&2
  exit 2
fi

rotation_date="${rotation_date:-$(date -u +%F)}"
rotation_index="$(rotation_index_for_date "${rotation_date}")"
resolved_out_dir="$(resolve_out_dir "${out_dir}")"
operator_root="${resolved_out_dir}/nightly-stress/${rotation_date}"
retained_dir="${operator_root}/retained_divergence_artifacts"
manifest_path="${operator_root}/nightly_stress_manifest.json"
summary_path="${operator_root}/nightly_stress_summary.txt"

mkdir -p "${operator_root}" "${retained_dir}"

run_records_file="$(mktemp)"
candidate_file="$(mktemp)"
trap 'rm -f "${run_records_file}" "${candidate_file}"' EXIT

total_scenarios=0
total_pass=0
total_unexpected=0
total_missing_expected=0
overall_exit=0

for ((offset = 0; offset < seed_count; offset++)); do
  derived_seed=$((root_seed + (rotation_index * seed_stride * seed_count) + (offset * seed_stride)))
  seed_root="${operator_root}/${derived_seed}"
  profile_root="${seed_root}/phase1-core"
  run_log="${seed_root}/phase1_core.stdout.log"

  mkdir -p "${seed_root}"

  set +e
  run_differential \
    --profile phase1-core \
    --seed "${derived_seed}" \
    --out-dir "${seed_root}" \
    2>&1 | tee "${run_log}"
  run_exit=${PIPESTATUS[0]}
  set -e

  runner_summary_path="${profile_root}/runner_summary.json"
  operator_summary_path="${profile_root}/operator_summary.txt"
  artifact_index_path="${profile_root}/artifact_index.json"
  aggregate_event_log_path="${profile_root}/differential_event_log.jsonl"
  missing_artifacts=()

  for required_artifact in \
    "${runner_summary_path}" \
    "${operator_summary_path}" \
    "${artifact_index_path}" \
    "${aggregate_event_log_path}"; do
    if [[ ! -f "${required_artifact}" ]]; then
      missing_artifacts+=("${required_artifact}")
    fi
  done

  missing_artifacts_json="$(json_array_from_args "${missing_artifacts[@]}")"

  if [[ "${#missing_artifacts[@]}" -ne 0 && ! -f "${runner_summary_path}" ]]; then
    overall_exit=1
    jq -nc \
      --argjson seed "${derived_seed}" \
      --argjson exit_code "${run_exit}" \
      --arg runner_summary_path "${runner_summary_path}" \
      --arg operator_summary_path "${operator_summary_path}" \
      --arg artifact_index_path "${artifact_index_path}" \
      --arg aggregate_event_log_path "${aggregate_event_log_path}" \
      --arg run_log_path "${run_log}" \
      --arg status "artifact_contract_regression" \
      --argjson missing_artifacts "${missing_artifacts_json}" \
      '{
        seed: $seed,
        exit_code: $exit_code,
        status: $status,
        runner_summary_path: $runner_summary_path,
        operator_summary_path: $operator_summary_path,
        artifact_index_path: $artifact_index_path,
        aggregate_event_log_path: $aggregate_event_log_path,
        run_log_path: $run_log_path,
        missing_artifacts: $missing_artifacts,
        scenario_count: 0,
        pass_count: 0,
        unexpected_divergence_count: 0,
        missing_expected_divergence_count: 0
      }' >> "${run_records_file}"
    continue
  fi

  scenario_count="$(jq -r '.scenario_count // 0' "${runner_summary_path}")"
  pass_count="$(jq -r '.pass_count // 0' "${runner_summary_path}")"
  unexpected_count="$(jq -r '.unexpected_divergence_count // 0' "${runner_summary_path}")"
  missing_expected_count="$(jq -r '.missing_expected_divergence_count // 0' "${runner_summary_path}")"
  replay_commands_json="$(jq -c '[(.scenarios // [])[] | .repro_commands[]?] | unique' "${runner_summary_path}")"

  total_scenarios=$((total_scenarios + scenario_count))
  total_pass=$((total_pass + pass_count))
  total_unexpected=$((total_unexpected + unexpected_count))
  total_missing_expected=$((total_missing_expected + missing_expected_count))

  run_status="pass"
  if [[ "${run_exit}" -ne 0 || "${unexpected_count}" -ne 0 || "${missing_expected_count}" -ne 0 ]]; then
    overall_exit=1
    run_status="failure"
  fi
  if [[ "${#missing_artifacts[@]}" -ne 0 ]]; then
    overall_exit=1
    run_status="artifact_contract_regression"
  fi

  jq -nc \
    --argjson seed "${derived_seed}" \
    --argjson exit_code "${run_exit}" \
    --arg status "${run_status}" \
    --arg runner_summary_path "${runner_summary_path}" \
    --arg operator_summary_path "${operator_summary_path}" \
    --arg artifact_index_path "${artifact_index_path}" \
    --arg aggregate_event_log_path "${aggregate_event_log_path}" \
    --arg run_log_path "${run_log}" \
    --argjson scenario_count "${scenario_count}" \
    --argjson pass_count "${pass_count}" \
    --argjson unexpected_divergence_count "${unexpected_count}" \
    --argjson missing_expected_divergence_count "${missing_expected_count}" \
    --argjson replay_commands "${replay_commands_json}" \
    --argjson missing_artifacts "${missing_artifacts_json}" \
    '{
      seed: $seed,
      exit_code: $exit_code,
      status: $status,
      runner_summary_path: $runner_summary_path,
      operator_summary_path: $operator_summary_path,
      artifact_index_path: $artifact_index_path,
      aggregate_event_log_path: $aggregate_event_log_path,
      run_log_path: $run_log_path,
      missing_artifacts: $missing_artifacts,
      scenario_count: $scenario_count,
      pass_count: $pass_count,
      unexpected_divergence_count: $unexpected_divergence_count,
      missing_expected_divergence_count: $missing_expected_divergence_count,
      replay_commands: $replay_commands
    }' >> "${run_records_file}"

  jq -c \
    --argjson seed "${derived_seed}" \
    '.scenarios[]
     | select(.status == "unexpected_divergence" or .status == "missing_expected_divergence")
     | {
         seed: $seed,
         scenario_id,
         status,
         summary_path,
         event_log_path,
         failures_path,
         deviations_path,
         repro_manifest_path,
         repro_commands,
         promotion_rule: (
           if .status == "unexpected_divergence"
           then "open_or_update_bead_with_retained_bundle"
           else "treat_as_guardrail_regression_before_claiming_semantic_improvement"
           end
         )
       }' "${runner_summary_path}" \
    | while read -r candidate; do
        candidate_name="$(jq -r '.seed | tostring' <<<"${candidate}")__$(sanitize_component "$(jq -r '.scenario_id' <<<"${candidate}")")"
        printf '%s\n' "${candidate}" > "${retained_dir}/${candidate_name}.json"
        printf '%s\n' "${candidate}" >> "${candidate_file}"
      done
done

retained_count="$(find "${retained_dir}" -maxdepth 1 -type f -name '*.json' | wc -l | tr -d ' ')"

jq -n \
  --arg schema_version "lab-live-differential-nightly-stress-v1" \
  --arg profile_id "nightly-stress" \
  --arg backing_cli_profile "phase1-core" \
  --arg operator_root "${operator_root}" \
  --arg rotation_date_utc "${rotation_date}" \
  --arg rotation_epoch_utc "2026-01-01" \
  --argjson rotation_index "${rotation_index}" \
  --argjson root_seed "${root_seed}" \
  --argjson seed_count "${seed_count}" \
  --argjson seed_stride "${seed_stride}" \
  --argjson total_runs "${seed_count}" \
  --argjson total_scenarios "${total_scenarios}" \
  --argjson total_pass "${total_pass}" \
  --argjson total_unexpected "${total_unexpected}" \
  --argjson total_missing_expected "${total_missing_expected}" \
  --argjson overall_exit "${overall_exit}" \
  --argjson retained_count "${retained_count}" \
  --slurpfile runs "${run_records_file}" \
  --slurpfile candidates "${candidate_file}" \
  '{
     schema_version: $schema_version,
     profile_id: $profile_id,
     backing_cli_profile: $backing_cli_profile,
     operator_root: $operator_root,
     rotation_date_utc: $rotation_date_utc,
     rotation_epoch_utc: $rotation_epoch_utc,
     rotation_index: $rotation_index,
     seed_policy: {
       root_seed: $root_seed,
       seed_count: $seed_count,
       seed_stride: $seed_stride,
       derived_seeds: ($runs | map(.seed))
     },
     retention: {
       local_retention_days: 14,
       ci_retention_days: 30,
       redaction_mode: "inherit docs/lab_live_divergence_taxonomy.md"
     },
     promotion_rules: [
       "unexpected_divergence => open or update a bead with the retained bundle pointer and replay command",
       "repeat or minimized witness => promote into the stable regression corpus once the scenario is reduced",
       "missing_expected_divergence => treat as a guardrail regression before claiming semantic improvement"
     ],
     summary: {
       total_runs: $total_runs,
       total_scenarios: $total_scenarios,
       total_pass: $total_pass,
       total_unexpected_divergence: $total_unexpected,
       total_missing_expected_divergence: $total_missing_expected,
       retained_divergence_artifacts: $retained_count,
       status: (if $overall_exit == 0 then "pass" else "failure" end)
     },
     runs: $runs,
     retained_divergence_artifacts: $candidates,
     replay_guidance: ($candidates | map(.repro_commands[]?) | unique),
     known_open_follow_up: "Unexpected divergences without an active bead must be recorded as a tracked investigation using the retained bundle pointer."
   }' > "${manifest_path}"

{
  echo "Nightly differential stress summary"
  echo "Rotation date: ${rotation_date}"
  echo "Rotation index: ${rotation_index}"
  echo "Backing CLI profile: phase1-core"
  echo "Root seed: ${root_seed}"
  echo "Seed count: ${seed_count}"
  echo "Seed stride: ${seed_stride}"
  echo "Status: $(jq -r '.summary.status' "${manifest_path}")"
  echo "Unexpected divergences: ${total_unexpected}"
  echo "Missing expected divergences: ${total_missing_expected}"
  echo "Retained divergence artifacts: ${retained_count}"
  echo "Manifest: ${manifest_path}"
  echo
  echo "Per-seed runs:"
  jq -r '.runs[] | "- seed \(.seed) [\(.status)]\n  runner_summary: \(.runner_summary_path)\n  operator_summary: \(.operator_summary_path)\n  artifact_index: \(.artifact_index_path)\n  run_log: \(.run_log_path)" + (if ((.missing_artifacts // []) | length) > 0 then "\n  missing_artifacts: " + ((.missing_artifacts // []) | join(", ")) else "" end)' "${manifest_path}"
  if [[ "${retained_count}" -gt 0 ]]; then
    echo
    echo "Promotion candidates:"
    jq -r '.retained_divergence_artifacts[] | "- seed \(.seed) \(.scenario_id) [\(.status)]\n  summary: \(.summary_path)\n  promotion_rule: \(.promotion_rule)\n  replay: \((.repro_commands // [])[0] // "<missing>")"' "${manifest_path}"
  fi
} > "${summary_path}"

if [[ "${json_mode}" -eq 1 ]]; then
  cat "${manifest_path}"
else
  cat "${summary_path}"
fi

exit "${overall_exit}"
