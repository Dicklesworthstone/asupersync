#!/usr/bin/env bash
set -euo pipefail

repo_path="$(pwd)"
fixture=""
output_dir=""
generated_at="2026-06-05T08:55:00Z"

usage() {
  printf 'usage: %s [--repo-path PATH] [--fixture PATH] [--output-dir PATH] [--generated-at RFC3339]\n' "$0" >&2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo-path)
      repo_path="$2"
      shift 2
      ;;
    --fixture)
      fixture="$2"
      shift 2
      ;;
    --output-dir)
      output_dir="$2"
      shift 2
      ;;
    --generated-at)
      generated_at="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf '[proof-lane-pressure-chaos:e2e] unknown argument: %s\n' "$1" >&2
      usage
      exit 2
      ;;
  esac
done

repo_path="$(cd "$repo_path" && pwd)"
if [[ -z "$fixture" ]]; then
  fixture="$repo_path/tests/fixtures/proof_lane_pressure_chaos/proof_lane_pressure_scenarios.json"
fi
if [[ -z "$output_dir" ]]; then
  output_dir="$repo_path/target/proof-lane-pressure-chaos-e2e"
fi

if [[ ! -f "$fixture" ]]; then
  printf '[proof-lane-pressure-chaos:e2e] fixture not found: %s\n' "$fixture" >&2
  exit 2
fi
if [[ ! -f "$repo_path/scripts/swarm_pressure_preflight_report.py" ]]; then
  printf '[proof-lane-pressure-chaos:e2e] preflight report script not found under repo: %s\n' "$repo_path" >&2
  exit 2
fi
if ! command -v jq >/dev/null 2>&1; then
  printf '[proof-lane-pressure-chaos:e2e] jq is required\n' >&2
  exit 2
fi

mkdir -p "$output_dir"

scenario_count="$(jq '.scenarios | length' "$fixture")"
if [[ "$scenario_count" -eq 0 ]]; then
  printf '[proof-lane-pressure-chaos:e2e] fixture has no scenarios: %s\n' "$fixture" >&2
  exit 2
fi

printf '[proof-lane-pressure-chaos:e2e] repo_path=%s\n' "$repo_path"
printf '[proof-lane-pressure-chaos:e2e] fixture=%s\n' "$fixture"
printf '[proof-lane-pressure-chaos:e2e] output_dir=%s\n' "$output_dir"
printf '[proof-lane-pressure-chaos:e2e] generated_at=%s\n' "$generated_at"
printf '[proof-lane-pressure-chaos:e2e] scenario_count=%s\n' "$scenario_count"

passed=0
for ((index = 0; index < scenario_count; index += 1)); do
  scenario_id="$(jq -r ".scenarios[$index].scenario_id" "$fixture")"
  scenario_dir="$output_dir/$scenario_id"
  scenario_file="$scenario_dir/scenario.json"
  preflight_file="$scenario_dir/preflight_input.json"
  report_file="$scenario_dir/preflight_report.json"
  mkdir -p "$scenario_dir"

  jq ".scenarios[$index]" "$fixture" > "$scenario_file"
  jq ".scenarios[$index].preflight_input" "$fixture" > "$preflight_file"

  expected_decision="$(jq -r '.expected_decision' "$scenario_file")"
  dimensions="$(jq -cr '.pressure_dimensions | sort' "$scenario_file")"
  facts="$(jq -c '.injected_pressure_facts' "$scenario_file")"

  printf '[proof-lane-pressure-chaos:e2e] scenario_id=%s\n' "$scenario_id"
  printf '[proof-lane-pressure-chaos:e2e] pressure_dimensions=%s\n' "$dimensions"
  printf '[proof-lane-pressure-chaos:e2e] injected_pressure_facts=%s\n' "$facts"
  printf '[proof-lane-pressure-chaos:e2e] expected_decision=%s\n' "$expected_decision"

  python3 "$repo_path/scripts/swarm_pressure_preflight_report.py" \
    --fixture "$preflight_file" \
    --repo-path "$repo_path" \
    --generated-at "$generated_at" \
    --output json \
    > "$report_file"

  actual_decision="$(jq -r '.operator_summary.decision' "$report_file")"
  expected_blockers="$(jq -c '.expected_blocker_kinds | sort' "$scenario_file")"
  actual_blockers="$(jq -c '[.blockers[].kind] | sort' "$report_file")"
  expected_warnings="$(jq -c '.expected_warning_kinds | sort' "$scenario_file")"
  actual_warnings="$(jq -c '[.warnings[].kind] | sort' "$report_file")"

  printf '[proof-lane-pressure-chaos:e2e] actual_decision=%s\n' "$actual_decision"
  printf '[proof-lane-pressure-chaos:e2e] blockers=%s\n' "$actual_blockers"
  jq -r '.blockers[]? | "[proof-lane-pressure-chaos:e2e] blocker kind=\(.kind) source=\(.source_kind) lane=\(.lane_id) path=\(.path) reason=\(.reason)"' "$report_file"
  printf '[proof-lane-pressure-chaos:e2e] warnings=%s\n' "$actual_warnings"
  jq -r '.warnings[]? | "[proof-lane-pressure-chaos:e2e] warning kind=\(.kind) source=\(.source_kind) lane=\(.lane_id) claim=\(.claim_id) reason=\(.reason)"' "$report_file"

  if [[ "$actual_decision" != "$expected_decision" ]]; then
    printf '[proof-lane-pressure-chaos:e2e] decision mismatch for %s: expected=%s actual=%s\n' "$scenario_id" "$expected_decision" "$actual_decision" >&2
    exit 1
  fi
  if [[ "$actual_blockers" != "$expected_blockers" ]]; then
    printf '[proof-lane-pressure-chaos:e2e] blocker mismatch for %s: expected=%s actual=%s\n' "$scenario_id" "$expected_blockers" "$actual_blockers" >&2
    exit 1
  fi
  if [[ "$actual_warnings" != "$expected_warnings" ]]; then
    printf '[proof-lane-pressure-chaos:e2e] warning mismatch for %s: expected=%s actual=%s\n' "$scenario_id" "$expected_warnings" "$actual_warnings" >&2
    exit 1
  fi

  passed=$((passed + 1))
  printf '[proof-lane-pressure-chaos:e2e] scenario_id=%s result=pass report=%s\n' "$scenario_id" "$report_file"
done

printf '[proof-lane-pressure-chaos:e2e] summary passed=%s failed=0\n' "$passed"
