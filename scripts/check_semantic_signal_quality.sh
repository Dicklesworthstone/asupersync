#!/usr/bin/env bash
# SEM-10.5 CI signal-quality gate.
#
# Measures deterministic replay instability, false-positive proxy rate, and
# runtime budget adherence. Emits concise terminal output with deep-log links
# plus a machine-readable JSON report for CI and local use.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

REPORT_PATH="$PROJECT_ROOT/target/semantic-verification/verification_report.json"
DASHBOARD_PATH="$PROJECT_ROOT/target/semantic-verification/flake/latest/variance_dashboard.json"
OUTPUT_PATH="$PROJECT_ROOT/target/semantic-verification/signal-quality/signal_quality_report.json"

MAX_FLAKE_RATE_PCT=0
MAX_FALSE_POSITIVE_RATE_PCT=5
MAX_RUNTIME_RATIO=1.0

usage() {
    cat <<'USAGE'
Usage: scripts/check_semantic_signal_quality.sh [options]

Options:
  --report <path>                   Verification report JSON path
  --dashboard <path>                Flake variance dashboard JSON path
  --output <path>                   Signal-quality output JSON path
  --max-flake-rate-pct <number>     Allowed unstable-suite rate percentage (default: 0)
  --max-false-positive-rate-pct <n> Allowed false-positive proxy percentage (default: 5)
  --max-runtime-ratio <number>      Allowed total_duration/runtime_budget ratio (default: 1.0)
  -h, --help                        Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --report)
            REPORT_PATH="${2:-}"
            shift 2
            ;;
        --dashboard)
            DASHBOARD_PATH="${2:-}"
            shift 2
            ;;
        --output)
            OUTPUT_PATH="${2:-}"
            shift 2
            ;;
        --max-flake-rate-pct)
            MAX_FLAKE_RATE_PCT="${2:-}"
            shift 2
            ;;
        --max-false-positive-rate-pct)
            MAX_FALSE_POSITIVE_RATE_PCT="${2:-}"
            shift 2
            ;;
        --max-runtime-ratio)
            MAX_RUNTIME_RATIO="${2:-}"
            shift 2
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

if ! command -v jq >/dev/null 2>&1; then
    echo "FATAL: jq is required" >&2
    exit 2
fi
if [[ ! -f "$REPORT_PATH" ]]; then
    echo "FATAL: verification report not found: $REPORT_PATH" >&2
    exit 2
fi
if [[ ! -f "$DASHBOARD_PATH" ]]; then
    echo "FATAL: variance dashboard not found: $DASHBOARD_PATH" >&2
    exit 2
fi

OUTPUT_DIR="$(dirname "$OUTPUT_PATH")"
mkdir -p "$OUTPUT_DIR"

report_base_dir="$(cd "$(dirname "$REPORT_PATH")" && pwd)"
dashboard_base_dir="$(cd "$(dirname "$DASHBOARD_PATH")" && pwd)"

runner_profile="$(jq -r '.profile // "unknown"' "$REPORT_PATH")"
runner_total_duration_s="$(jq -r '.total_duration_s // 0' "$REPORT_PATH")"
runner_budget_s="$(jq -r '.profile_contract.runtime_budget_s // 0' "$REPORT_PATH")"
runner_report_dir_raw="$(jq -r '.report_dir // ""' "$REPORT_PATH")"

if [[ -n "$runner_report_dir_raw" && "$runner_report_dir_raw" != /* ]]; then
    runner_report_dir="$report_base_dir/$runner_report_dir_raw"
elif [[ -n "$runner_report_dir_raw" ]]; then
    runner_report_dir="$runner_report_dir_raw"
else
    runner_report_dir="$report_base_dir"
fi

suite_count="$(jq -r '.suite_count // 0' "$DASHBOARD_PATH")"
unstable_suite_count="$(jq -r '.unstable_suite_count // 0' "$DASHBOARD_PATH")"
false_positive_proxy_count="$(jq -r '[.suites[]? | select((.unstable == true) and ((.outcomes.fail // 0) == 0))] | length' "$DASHBOARD_PATH")"

flake_rate_pct="0"
false_positive_proxy_rate_pct="0"
if [[ "$suite_count" -gt 0 ]]; then
    flake_rate_pct="$(awk -v unstable="$unstable_suite_count" -v total="$suite_count" 'BEGIN { printf "%.2f", (unstable * 100.0) / total }')"
    false_positive_proxy_rate_pct="$(awk -v fp="$false_positive_proxy_count" -v total="$suite_count" 'BEGIN { printf "%.2f", (fp * 100.0) / total }')"
fi

runtime_ratio="0.000"
if [[ "$runner_budget_s" -gt 0 ]]; then
    runtime_ratio="$(awk -v total="$runner_total_duration_s" -v budget="$runner_budget_s" 'BEGIN { printf "%.3f", total / budget }')"
fi

mapfile -t required_artifacts < <(jq -r '.profile_contract.required_artifacts // [] | .[]' "$REPORT_PATH")
existing_required_artifacts=()
missing_required_artifacts=()
for artifact in "${required_artifacts[@]}"; do
    artifact_path="$runner_report_dir/$artifact"
    if [[ -e "$artifact_path" ]]; then
        existing_required_artifacts+=("$artifact_path")
    else
        missing_required_artifacts+=("$artifact_path")
    fi
done

variance_events_raw="$(jq -r '.artifacts.variance_events_ndjson // ""' "$DASHBOARD_PATH")"
summary_raw="$(jq -r '.artifacts.summary // ""' "$DASHBOARD_PATH")"
if [[ -n "$variance_events_raw" && "$variance_events_raw" != /* ]]; then
    variance_events_path="$dashboard_base_dir/$variance_events_raw"
else
    variance_events_path="$variance_events_raw"
fi
if [[ -n "$summary_raw" && "$summary_raw" != /* ]]; then
    summary_path="$dashboard_base_dir/$summary_raw"
else
    summary_path="$summary_raw"
fi

failures=()
if awk -v a="$flake_rate_pct" -v b="$MAX_FLAKE_RATE_PCT" 'BEGIN { exit !(a > b) }'; then
    failures+=("flake_rate_pct exceeds threshold (${flake_rate_pct}% > ${MAX_FLAKE_RATE_PCT}%)")
fi
if awk -v a="$false_positive_proxy_rate_pct" -v b="$MAX_FALSE_POSITIVE_RATE_PCT" 'BEGIN { exit !(a > b) }'; then
    failures+=("false_positive_proxy_rate_pct exceeds threshold (${false_positive_proxy_rate_pct}% > ${MAX_FALSE_POSITIVE_RATE_PCT}%)")
fi
if [[ "$runner_budget_s" -le 0 ]]; then
    failures+=("runtime budget missing or invalid (profile_contract.runtime_budget_s <= 0)")
elif awk -v a="$runtime_ratio" -v b="$MAX_RUNTIME_RATIO" 'BEGIN { exit !(a > b) }'; then
    failures+=("runtime_ratio exceeds threshold (${runtime_ratio} > ${MAX_RUNTIME_RATIO})")
fi
if [[ ${#missing_required_artifacts[@]} -gt 0 ]]; then
    failures+=("missing required runner artifacts (${#missing_required_artifacts[@]})")
fi
if [[ -z "$variance_events_path" || ! -f "$variance_events_path" ]]; then
    failures+=("variance events link missing or unreadable")
fi
if [[ -z "$summary_path" || ! -f "$summary_path" ]]; then
    failures+=("variance summary link missing or unreadable")
fi

status="pass"
if [[ ${#failures[@]} -gt 0 ]]; then
    status="fail"
fi

existing_artifacts_json="$(printf '%s\n' "${existing_required_artifacts[@]:-}" | jq -R . | jq -s 'map(select(length > 0))')"
missing_artifacts_json="$(printf '%s\n' "${missing_required_artifacts[@]:-}" | jq -R . | jq -s 'map(select(length > 0))')"
failures_json="$(printf '%s\n' "${failures[@]:-}" | jq -R . | jq -s 'map(select(length > 0))')"

jq -n \
    --arg schema_version "semantic-signal-quality-v1" \
    --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg status "$status" \
    --arg report_path "$REPORT_PATH" \
    --arg dashboard_path "$DASHBOARD_PATH" \
    --arg output_path "$OUTPUT_PATH" \
    --arg runner_profile "$runner_profile" \
    --argjson suite_count "$suite_count" \
    --argjson unstable_suite_count "$unstable_suite_count" \
    --argjson false_positive_proxy_count "$false_positive_proxy_count" \
    --argjson flake_rate_pct "$flake_rate_pct" \
    --argjson false_positive_proxy_rate_pct "$false_positive_proxy_rate_pct" \
    --argjson total_duration_s "$runner_total_duration_s" \
    --argjson runtime_budget_s "$runner_budget_s" \
    --argjson runtime_ratio "$runtime_ratio" \
    --argjson max_flake_rate_pct "$MAX_FLAKE_RATE_PCT" \
    --argjson max_false_positive_rate_pct "$MAX_FALSE_POSITIVE_RATE_PCT" \
    --argjson max_runtime_ratio "$MAX_RUNTIME_RATIO" \
    --arg runner_report_dir "$runner_report_dir" \
    --arg variance_events_path "$variance_events_path" \
    --arg summary_path "$summary_path" \
    --arg maintenance_doc "$PROJECT_ROOT/docs/semantic_ci_signal_quality.md" \
    --argjson existing_artifacts "$existing_artifacts_json" \
    --argjson missing_artifacts "$missing_artifacts_json" \
    --argjson failures "$failures_json" \
    '{
      schema_version:$schema_version,
      generated_at:$generated_at,
      status:$status,
      inputs:{
        verification_report:$report_path,
        variance_dashboard:$dashboard_path
      },
      metrics:{
        runner_profile:$runner_profile,
        suite_count:$suite_count,
        unstable_suite_count:$unstable_suite_count,
        flake_rate_pct:$flake_rate_pct,
        false_positive_proxy_count:$false_positive_proxy_count,
        false_positive_proxy_rate_pct:$false_positive_proxy_rate_pct,
        total_duration_s:$total_duration_s,
        runtime_budget_s:$runtime_budget_s,
        runtime_ratio:$runtime_ratio
      },
      thresholds:{
        max_flake_rate_pct:$max_flake_rate_pct,
        max_false_positive_rate_pct:$max_false_positive_rate_pct,
        max_runtime_ratio:$max_runtime_ratio
      },
      diagnostics_links:{
        runner_report_dir:$runner_report_dir,
        existing_required_artifacts:$existing_artifacts,
        missing_required_artifacts:$missing_artifacts,
        variance_events_ndjson:$variance_events_path,
        variance_summary:$summary_path
      },
      maintenance_guidance:{
        document:$maintenance_doc
      },
      rerun_commands:[
        "scripts/run_semantic_verification.sh --profile full --json",
        "scripts/run_semantic_flake_detector.sh --iterations 5 --json",
        ("scripts/check_semantic_signal_quality.sh --report " + $report_path + " --dashboard " + $dashboard_path + " --output " + $output_path)
      ],
      failures:$failures
    }' > "$OUTPUT_PATH"

echo "[semantic-signal-quality] status=$status profile=$runner_profile flake_rate_pct=$flake_rate_pct false_positive_proxy_rate_pct=$false_positive_proxy_rate_pct runtime_ratio=$runtime_ratio"
echo "[semantic-signal-quality] report=$REPORT_PATH"
echo "[semantic-signal-quality] dashboard=$DASHBOARD_PATH"
echo "[semantic-signal-quality] details=$OUTPUT_PATH"

if [[ ${#existing_required_artifacts[@]} -gt 0 ]]; then
    echo "[semantic-signal-quality] deep links:"
    for artifact_path in "${existing_required_artifacts[@]}"; do
        echo "  - $artifact_path"
    done
    echo "  - $variance_events_path"
    echo "  - $summary_path"
fi

if [[ "$status" != "pass" ]]; then
    exit 1
fi

exit 0
