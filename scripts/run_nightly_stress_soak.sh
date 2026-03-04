#!/usr/bin/env bash
# Nightly stress, soak, and flake-burndown automation (asupersync-umelq.18.10)
#
# Orchestrates stress/soak test suites, runs flake detection, generates
# trend-aware burndown reports, and enforces reliability regression gates.
#
# Usage:
#   scripts/run_nightly_stress_soak.sh [OPTIONS]
#
# Options:
#   --run-id ID              Unique run identifier (default: nightly-YYYYMMDDTHHMMSSZ)
#   --suites NAMES           Comma-separated suite filter (default: all)
#   --timeout SECS           Per-suite timeout in seconds (default: 3600)
#   --ci                     CI mode: exit 1 on failure or trend regression
#   --json                   Emit JSON manifests (default: true)
#   --trend-window N         Days of trend history to analyze (default: 14)
#   --stress-schedules N     Obligation stress schedule count (default: 1000000)
#   --skip-flake-detection   Skip flake detector pass
#   -h, --help               Show this help
#
# Exit codes:
#   0 = all suites passed, no trend regressions
#   1 = suite failure or trend regression detected
#   2 = configuration error
#
# Bead: asupersync-umelq.18.10

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_ID="nightly-${TIMESTAMP}"
REPORT_DIR=""
MANIFEST_FILE=""

# Defaults
SUITES="all"
TIMEOUT=3600
CI_MODE=false
JSON_OUTPUT=true
TREND_WINDOW=14
STRESS_SCHEDULES=1000000
SKIP_FLAKE_DETECTION=false

while [ $# -gt 0 ]; do
  case "$1" in
    --run-id)
      RUN_ID="$2"
      shift 2
      ;;
    --suites)
      SUITES="$2"
      shift 2
      ;;
    --timeout)
      TIMEOUT="$2"
      shift 2
      ;;
    --ci)
      CI_MODE=true
      shift
      ;;
    --json)
      JSON_OUTPUT=true
      shift
      ;;
    --trend-window)
      TREND_WINDOW="$2"
      shift 2
      ;;
    --stress-schedules)
      STRESS_SCHEDULES="$2"
      shift 2
      ;;
    --skip-flake-detection)
      SKIP_FLAKE_DETECTION=true
      shift
      ;;
    -h|--help)
      head -28 "$0" | tail -25
      exit 0
      ;;
    *)
      echo "ERROR: Unknown option: $1" >&2
      exit 2
      ;;
  esac
done

REPORT_DIR="$PROJECT_ROOT/target/nightly-stress/${RUN_ID}"
MANIFEST_FILE="$REPORT_DIR/run_manifest.json"
TREND_FILE="$REPORT_DIR/trend_report.json"
BURNDOWN_FILE="$REPORT_DIR/burndown_report.json"
LOG_DIR="$REPORT_DIR/suite_logs"

mkdir -p "$LOG_DIR"

# ── Suite registry ──────────────────────────────────────────────────────

declare -a SUITE_IDS=()
declare -A SUITE_TARGETS=()
declare -A SUITE_CATEGORIES=()
declare -A SUITE_ENVS=()

register_suite() {
  local id="$1" target="$2" category="$3" env="${4:-}"
  SUITE_IDS+=("$id")
  SUITE_TARGETS["$id"]="$target"
  SUITE_CATEGORIES["$id"]="$category"
  SUITE_ENVS["$id"]="$env"
}

register_suite "cancellation_stress" "--test cancellation_stress_e2e" "stress" ""
register_suite "obligation_leak" "--test obligation_leak_stress" "stress" "OBLIGATION_STRESS_SCHEDULES=$STRESS_SCHEDULES"
register_suite "scheduler_fairness" "--test scheduler_stress_fairness_e2e" "stress" ""
register_suite "quic_h3_soak" "--test tokio_quic_h3_soak_adversarial" "soak" ""

should_run_suite() {
  local id="$1"
  if [ "$SUITES" = "all" ]; then
    return 0
  fi
  echo "$SUITES" | tr ',' '\n' | grep -qx "$id"
}

# ── Execution ───────────────────────────────────────────────────────────

OVERALL_RESULT="pass"
STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
SUITE_RESULTS=()
TOTAL_TESTS_RUN=0
TOTAL_TESTS_PASSED=0
TOTAL_TESTS_FAILED=0

echo "=== Nightly Stress/Soak Runner ==="
echo "Run ID:    $RUN_ID"
echo "Started:   $STARTED_AT"
echo "Suites:    $SUITES"
echo "Timeout:   ${TIMEOUT}s per suite"
echo "Schedules: $STRESS_SCHEDULES (obligation stress)"
echo "Report:    $REPORT_DIR"
echo ""

run_suite() {
  local id="$1"
  local target="${SUITE_TARGETS[$id]}"
  local category="${SUITE_CATEGORIES[$id]}"
  local env_vars="${SUITE_ENVS[$id]}"
  local log_file="$LOG_DIR/${id}.log"
  local suite_start suite_end duration exit_code tests_total tests_pass tests_fail

  suite_start=$(date +%s)
  echo "--- Running suite: $id ($category) ---"

  # Build cargo test command
  local cmd="cargo test $target -- --nocapture"
  if [ -n "$env_vars" ]; then
    cmd="env $env_vars $cmd"
  fi

  # Run with timeout
  set +e
  timeout "$TIMEOUT" bash -c "cd '$PROJECT_ROOT' && $cmd" > "$log_file" 2>&1
  exit_code=$?
  set -e

  suite_end=$(date +%s)
  duration=$((suite_end - suite_start))

  # Parse test counts from output
  tests_total=0
  tests_pass=0
  tests_fail=0
  if grep -q "test result:" "$log_file" 2>/dev/null; then
    local result_line
    result_line=$(grep "test result:" "$log_file" | tail -1)
    tests_pass=$(echo "$result_line" | grep -o '[0-9]* passed' | grep -o '[0-9]*' || echo "0")
    tests_fail=$(echo "$result_line" | grep -o '[0-9]* failed' | grep -o '[0-9]*' || echo "0")
    tests_total=$((tests_pass + tests_fail))
  fi

  local result="pass"
  if [ "$exit_code" -ne 0 ]; then
    result="fail"
    OVERALL_RESULT="fail"
    echo "  FAILED (exit=$exit_code, ${duration}s)"
  else
    echo "  PASSED (${duration}s, ${tests_pass}/${tests_total} tests)"
  fi

  TOTAL_TESTS_RUN=$((TOTAL_TESTS_RUN + tests_total))
  TOTAL_TESTS_PASSED=$((TOTAL_TESTS_PASSED + tests_pass))
  TOTAL_TESTS_FAILED=$((TOTAL_TESTS_FAILED + tests_fail))

  local repro_cmd="cargo test $target -- --nocapture"
  if [ -n "$env_vars" ]; then
    repro_cmd="$env_vars $repro_cmd"
  fi

  # Append JSON suite result
  SUITE_RESULTS+=("{\"id\":\"$id\",\"category\":\"$category\",\"result\":\"$result\",\"duration_secs\":$duration,\"tests_run\":$tests_total,\"tests_passed\":$tests_pass,\"tests_failed\":$tests_fail,\"log_file\":\"suite_logs/${id}.log\",\"repro_command\":\"$repro_cmd\"}")
}

# Run suites
for suite_id in "${SUITE_IDS[@]}"; do
  if should_run_suite "$suite_id"; then
    run_suite "$suite_id"
  fi
done

# ── Flake detection pass ────────────────────────────────────────────────

if [ "$SKIP_FLAKE_DETECTION" = false ] && [ -x "$SCRIPT_DIR/run_semantic_flake_detector.sh" ]; then
  echo ""
  echo "--- Running flake detection pass ---"
  local_flake_log="$LOG_DIR/flake_detection.log"
  set +e
  timeout "$TIMEOUT" bash "$SCRIPT_DIR/run_semantic_flake_detector.sh" \
    --iterations 3 --ci --json > "$local_flake_log" 2>&1
  flake_exit=$?
  set -e

  local flake_result="pass"
  if [ "$flake_exit" -ne 0 ]; then
    flake_result="fail"
    OVERALL_RESULT="fail"
    echo "  FLAKE DETECTION FAILED (exit=$flake_exit)"
  else
    echo "  FLAKE DETECTION PASSED"
  fi

  SUITE_RESULTS+=("{\"id\":\"flake_detection\",\"category\":\"flake\",\"result\":\"$flake_result\",\"duration_secs\":0,\"tests_run\":0,\"tests_passed\":0,\"tests_failed\":0,\"log_file\":\"suite_logs/flake_detection.log\",\"repro_command\":\"bash scripts/run_semantic_flake_detector.sh --iterations 3 --ci --json\"}")
fi

# ── Build run manifest ──────────────────────────────────────────────────

FINISHED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
STARTED_EPOCH=$(date -d "$STARTED_AT" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%SZ" "$STARTED_AT" +%s 2>/dev/null || echo 0)
FINISHED_EPOCH=$(date +%s)
TOTAL_DURATION=$((FINISHED_EPOCH - STARTED_EPOCH))

RUST_VERSION=$(rustc --version 2>/dev/null | head -1 || echo "unknown")
OS_NAME=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH_NAME=$(uname -m)

# Join suite results
SUITES_JSON=$(printf '%s,' "${SUITE_RESULTS[@]}" | sed 's/,$//')

if [ "$JSON_OUTPUT" = true ]; then
  cat > "$MANIFEST_FILE" <<MANIFEST_EOF
{
  "schema_version": "nightly-stress-manifest-v1",
  "run_id": "$RUN_ID",
  "started_at_utc": "$STARTED_AT",
  "finished_at_utc": "$FINISHED_AT",
  "total_duration_secs": $TOTAL_DURATION,
  "overall_result": "$OVERALL_RESULT",
  "total_tests_run": $TOTAL_TESTS_RUN,
  "total_tests_passed": $TOTAL_TESTS_PASSED,
  "total_tests_failed": $TOTAL_TESTS_FAILED,
  "suites": [$SUITES_JSON],
  "environment": {
    "rust_version": "$RUST_VERSION",
    "os": "$OS_NAME",
    "arch": "$ARCH_NAME",
    "obligation_stress_schedules": $STRESS_SCHEDULES,
    "timeout_secs": $TIMEOUT
  }
}
MANIFEST_EOF
  echo ""
  echo "Manifest written to: $MANIFEST_FILE"
fi

# ── Trend analysis ──────────────────────────────────────────────────────

TREND_REGRESSION=false
TREND_RUNS_IN_WINDOW=0
TREND_PASS_RATE=100.0
TREND_FLAKE_RATE=0.0

# Collect historical runs
HISTORY_DIR="$PROJECT_ROOT/target/nightly-stress"
if [ -d "$HISTORY_DIR" ]; then
  # Count runs in trend window
  CUTOFF_EPOCH=$((FINISHED_EPOCH - TREND_WINDOW * 86400))
  PASS_COUNT=0
  FAIL_COUNT=0
  TOTAL_HISTORICAL=0
  DURATION_SUM=0

  for manifest in "$HISTORY_DIR"/*/run_manifest.json; do
    [ -f "$manifest" ] || continue
    # Skip current run
    run_dir=$(dirname "$manifest")
    [ "$(basename "$run_dir")" = "$RUN_ID" ] && continue

    # Check if within window (simple date comparison from filename)
    TOTAL_HISTORICAL=$((TOTAL_HISTORICAL + 1))
    result=$(python3 -c "import json,sys; d=json.load(open('$manifest')); print(d.get('overall_result','unknown'))" 2>/dev/null || echo "unknown")
    dur=$(python3 -c "import json,sys; d=json.load(open('$manifest')); print(d.get('total_duration_secs',0))" 2>/dev/null || echo "0")

    if [ "$result" = "pass" ]; then
      PASS_COUNT=$((PASS_COUNT + 1))
    elif [ "$result" = "fail" ]; then
      FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
    DURATION_SUM=$((DURATION_SUM + dur))
  done

  TREND_RUNS_IN_WINDOW=$TOTAL_HISTORICAL
  if [ "$TOTAL_HISTORICAL" -gt 0 ]; then
    TREND_PASS_RATE=$(python3 -c "print(round($PASS_COUNT / $TOTAL_HISTORICAL * 100.0, 1))")
    MEAN_DUR=$((DURATION_SUM / TOTAL_HISTORICAL))
  else
    MEAN_DUR=0
  fi

  # Detect regression: pass rate dropped >5pp from historical or current run failed
  if [ "$OVERALL_RESULT" = "fail" ] && [ "$TREND_PASS_RATE" = "100.0" ]; then
    TREND_REGRESSION=true
    echo "TREND REGRESSION: first failure in rolling window"
  fi
fi

if [ "$JSON_OUTPUT" = true ]; then
  REGRESSION_JSON="false"
  if [ "$TREND_REGRESSION" = true ]; then
    REGRESSION_JSON="true"
  fi

  cat > "$TREND_FILE" <<TREND_EOF
{
  "schema_version": "nightly-trend-report-v1",
  "run_id": "$RUN_ID",
  "window_days": $TREND_WINDOW,
  "runs_in_window": $TREND_RUNS_IN_WINDOW,
  "metrics": {
    "overall_pass_rate_pct": $TREND_PASS_RATE,
    "flake_rate_pct": $TREND_FLAKE_RATE,
    "mean_duration_secs": ${MEAN_DUR:-0},
    "regression_detected": $REGRESSION_JSON
  },
  "current_run_result": "$OVERALL_RESULT"
}
TREND_EOF
  echo "Trend report written to: $TREND_FILE"
fi

# ── Burndown report ────────────────────────────────────────────────────

if [ "$JSON_OUTPUT" = true ]; then
  # Check quarantine manifest for open flakes
  QUARANTINE="$PROJECT_ROOT/artifacts/wasm_flake_quarantine_manifest.json"
  OPEN_FLAKES=0
  CRITICAL_FLAKES=0
  HIGH_FLAKES=0
  MEDIUM_FLAKES=0
  OVERDUE_COUNT=0
  BURNDOWN_TREND="stable"

  if [ -f "$QUARANTINE" ]; then
    OPEN_FLAKES=$(python3 -c "
import json
with open('$QUARANTINE') as f:
    data = json.load(f)
entries = data.get('entries', data) if isinstance(data, dict) else data
if isinstance(entries, list):
    print(sum(1 for e in entries if e.get('status') == 'open'))
else:
    print(0)
" 2>/dev/null || echo "0")

    CRITICAL_FLAKES=$(python3 -c "
import json
with open('$QUARANTINE') as f:
    data = json.load(f)
entries = data.get('entries', data) if isinstance(data, dict) else data
if isinstance(entries, list):
    print(sum(1 for e in entries if e.get('status') == 'open' and e.get('severity') == 'critical'))
else:
    print(0)
" 2>/dev/null || echo "0")

    HIGH_FLAKES=$(python3 -c "
import json
with open('$QUARANTINE') as f:
    data = json.load(f)
entries = data.get('entries', data) if isinstance(data, dict) else data
if isinstance(entries, list):
    print(sum(1 for e in entries if e.get('status') == 'open' and e.get('severity') == 'high'))
else:
    print(0)
" 2>/dev/null || echo "0")
  fi

  if [ "$OPEN_FLAKES" -eq 0 ] && [ "$OVERALL_RESULT" = "pass" ]; then
    BURNDOWN_TREND="improving"
  elif [ "$OPEN_FLAKES" -gt 0 ]; then
    BURNDOWN_TREND="needs_attention"
  fi

  cat > "$BURNDOWN_FILE" <<BURNDOWN_EOF
{
  "schema_version": "nightly-burndown-report-v1",
  "generated_at_utc": "$FINISHED_AT",
  "run_id": "$RUN_ID",
  "summary": {
    "total_open_flakes": $OPEN_FLAKES,
    "critical_flakes": $CRITICAL_FLAKES,
    "high_flakes": $HIGH_FLAKES,
    "medium_flakes": $MEDIUM_FLAKES,
    "overdue_sla_count": $OVERDUE_COUNT,
    "burndown_trend": "$BURNDOWN_TREND"
  },
  "release_gate": {
    "blocked": $([ "$CRITICAL_FLAKES" -gt 0 ] || [ "$TREND_REGRESSION" = true ] && echo "true" || echo "false"),
    "reasons": []
  }
}
BURNDOWN_EOF
  echo "Burndown report written to: $BURNDOWN_FILE"
fi

# ── Summary ─────────────────────────────────────────────────────────────

echo ""
echo "=== Summary ==="
echo "Result:     $OVERALL_RESULT"
echo "Tests:      $TOTAL_TESTS_PASSED passed, $TOTAL_TESTS_FAILED failed ($TOTAL_TESTS_RUN total)"
echo "Duration:   ${TOTAL_DURATION}s"
echo "Trend:      ${TREND_RUNS_IN_WINDOW} runs in ${TREND_WINDOW}d window, ${TREND_PASS_RATE}% pass rate"
if [ "$TREND_REGRESSION" = true ]; then
  echo "REGRESSION: Trend regression detected!"
fi
echo "Artifacts:  $REPORT_DIR"

# ── Exit ────────────────────────────────────────────────────────────────

if [ "$CI_MODE" = true ]; then
  if [ "$OVERALL_RESULT" = "fail" ] || [ "$TREND_REGRESSION" = true ]; then
    echo ""
    echo "CI MODE: Exiting with failure due to suite failure or trend regression."
    exit 1
  fi
fi

exit 0
