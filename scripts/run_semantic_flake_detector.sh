#!/usr/bin/env bash
# Deterministic replay flake detector + variance dashboard (SEM-12.15)
#
# Runs deterministic replay suites repeatedly, detects instability signals,
# and emits a machine-readable variance dashboard for CI and audit workflows.
#
# Usage:
#   scripts/run_semantic_flake_detector.sh [OPTIONS]
#
# Options:
#   --iterations N         Number of runs per suite (default: 5)
#   --seed N               Seed tag recorded in artifacts (default: 4242)
#   --suite NAME           Run one suite only (witness_seed_equivalence|cross_seed_replay)
#   --ci                   CI mode (unstable/failing suite => exit 1)
#   --json                 Emit JSON dashboard (default: true)
#   --verbose              Print suite logs on failure/instability
#   --duration-threshold P Duration spread threshold percent (default: 25)
#   -h, --help             Show this help
#
# Exit codes:
#   0 = all suites stable and passing
#   1 = failure/instability detected
#   2 = configuration error
#
# Bead: asupersync-3cddg.12.15

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_ID="sem-flake-${TIMESTAMP}"
REPORT_DIR="$PROJECT_ROOT/target/semantic-verification/flake/${RUN_ID}"
DASHBOARD_FILE="$REPORT_DIR/variance_dashboard.json"
EVENTS_FILE="$REPORT_DIR/variance_events.ndjson"
SUMMARY_FILE="$REPORT_DIR/summary.txt"

ITERATIONS=5
SEED=4242
SUITE_FILTER=""
CI_MODE=false
JSON_OUTPUT=true
VERBOSE=false
DURATION_THRESHOLD_PCT=25

while [ $# -gt 0 ]; do
  case "$1" in
    --iterations)
      ITERATIONS="$2"
      shift 2
      ;;
    --seed)
      SEED="$2"
      shift 2
      ;;
    --suite)
      SUITE_FILTER="$2"
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
    --verbose)
      VERBOSE=true
      shift
      ;;
    --duration-threshold)
      DURATION_THRESHOLD_PCT="$2"
      shift 2
      ;;
    -h|--help)
      head -38 "$0" | tail -35
      exit 0
      ;;
    *)
      echo "ERROR: unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if ! [[ "$ITERATIONS" =~ ^[0-9]+$ ]] || [ "$ITERATIONS" -lt 2 ]; then
  echo "ERROR: --iterations must be an integer >= 2 (got '$ITERATIONS')" >&2
  exit 2
fi

if ! [[ "$SEED" =~ ^[0-9]+$ ]]; then
  echo "ERROR: --seed must be an unsigned integer (got '$SEED')" >&2
  exit 2
fi

if ! [[ "$DURATION_THRESHOLD_PCT" =~ ^[0-9]+$ ]]; then
  echo "ERROR: --duration-threshold must be an integer percent (got '$DURATION_THRESHOLD_PCT')" >&2
  exit 2
fi

mkdir -p "$REPORT_DIR"
: > "$EVENTS_FILE"

RCH_BIN="${RCH_BIN:-rch}"
CARGO_BIN="${CARGO_BIN:-cargo}"
RCH_LOCAL_FALLBACK_PATTERN='^\[RCH\] local \(|falling back to local|local fallback|fallback to local|executing locally'
declare -A SUITE_WITNESS
declare -A SUITE_SCENARIO

SUITE_WITNESS[witness_seed_equivalence]="W7.1"
SUITE_SCENARIO[witness_seed_equivalence]="W7.1"

SUITE_WITNESS[cross_seed_replay]="W7.1"
SUITE_SCENARIO[cross_seed_replay]="cross-seed-replay"

if ! command -v "$RCH_BIN" >/dev/null 2>&1; then
  echo "ERROR: rch is required and was not found at: $RCH_BIN" >&2
  exit 2
fi

render_command() {
  local rendered
  printf -v rendered '%q ' "$@"
  printf '%s' "${rendered% }"
}

build_suite_command_argv() {
  local suite="$1"
  local output_name="$2"
  local -n output_ref="$output_name"
  local safe_suite="${suite//[^A-Za-z0-9_]/_}"

  # Contract marker for source-text tests: rch exec --
  case "$suite" in
    witness_seed_equivalence)
      output_ref=(
        "$RCH_BIN"
        exec
        --
        env
        "CARGO_INCREMENTAL=0"
        "CARGO_PROFILE_TEST_DEBUG=0"
        "RUSTFLAGS=-D warnings -C debuginfo=0"
        "CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_semantic_flake_${safe_suite}"
        "$CARGO_BIN"
        test
        -p
        asupersync
        --test
        semantic_witness_replay_e2e
        e2e_w7_1_seed_equivalence
        --
        --nocapture
      )
      ;;
    cross_seed_replay)
      output_ref=(
        "$RCH_BIN"
        exec
        --
        env
        "CARGO_INCREMENTAL=0"
        "CARGO_PROFILE_TEST_DEBUG=0"
        "RUSTFLAGS=-D warnings -C debuginfo=0"
        "CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_semantic_flake_${safe_suite}"
        "$CARGO_BIN"
        test
        -p
        asupersync
        --test
        replay_e2e_suite
        cross_seed_replay_suite
        --
        --nocapture
      )
      ;;
    *)
      echo "ERROR: unsupported suite '$suite'" >&2
      exit 2
      ;;
  esac
}

SUITES=("witness_seed_equivalence" "cross_seed_replay")

if [ -n "$SUITE_FILTER" ]; then
  case "$SUITE_FILTER" in
    witness_seed_equivalence|cross_seed_replay)
      SUITES=("$SUITE_FILTER")
      ;;
    *)
      echo "ERROR: unknown suite '$SUITE_FILTER'" >&2
      exit 2
      ;;
  esac
fi

declare -A PASS_COUNT
declare -A FAIL_COUNT
declare -A SKIP_COUNT
declare -A MIN_MS
declare -A MAX_MS
declare -A SUM_MS
declare -A LOG_PATHS
declare -A STATUS_TRACE
declare -A HAS_TIMEOUT
declare -A HAS_PANIC
declare -A HAS_DIVERGENCE
declare -A UNSTABLE
declare -A UNSTABLE_REASONS
declare -A DURATION_SPREAD_PCT

RUN_FAILED=0
UNSTABLE_COUNT=0

echo "=== SEM-12.15 deterministic replay flake detector ==="
echo "Run ID: $RUN_ID"
echo "Iterations per suite: $ITERATIONS"
echo "Report dir: $REPORT_DIR"
echo "Offload mode: rch"
echo ""

for suite in "${SUITES[@]}"; do
  declare -a cmd_argv=()
  build_suite_command_argv "$suite" cmd_argv
  cmd="$(render_command "${cmd_argv[@]}")"
  scenario_id="${SUITE_SCENARIO[$suite]}"
  suite_dir="$REPORT_DIR/$suite"
  mkdir -p "$suite_dir"

  PASS_COUNT["$suite"]=0
  FAIL_COUNT["$suite"]=0
  SKIP_COUNT["$suite"]=0
  SUM_MS["$suite"]=0
  MIN_MS["$suite"]=-1
  MAX_MS["$suite"]=0
  LOG_PATHS["$suite"]=""
  STATUS_TRACE["$suite"]=""
  HAS_TIMEOUT["$suite"]=false
  HAS_PANIC["$suite"]=false
  HAS_DIVERGENCE["$suite"]=false

  echo "--- suite: $suite"
  echo "command: $cmd"

  for i in $(seq 1 "$ITERATIONS"); do
    log_file="$suite_dir/run_${i}.log"
    start_ns="$(date +%s%N)"

    if "${cmd_argv[@]}" >"$log_file" 2>&1; then
      exit_code=0
    else
      exit_code=$?
    fi

    end_ns="$(date +%s%N)"
    duration_ms=$(((end_ns - start_ns) / 1000000))

    if grep -Eiq "$RCH_LOCAL_FALLBACK_PATTERN" "$log_file" 2>/dev/null; then
      echo "rch local fallback detected; refusing local cargo execution" > "$suite_dir/run_${i}_rch_local_fallback.txt"
      exit_code=86
    fi

    status="pass"
    if [ "$exit_code" -ne 0 ]; then
      status="fail"
      RUN_FAILED=1
    elif grep -qi "SKIP:" "$log_file"; then
      status="skip"
    fi

    case "$status" in
      pass) PASS_COUNT["$suite"]=$((PASS_COUNT["$suite"] + 1)) ;;
      fail) FAIL_COUNT["$suite"]=$((FAIL_COUNT["$suite"] + 1)) ;;
      skip) SKIP_COUNT["$suite"]=$((SKIP_COUNT["$suite"] + 1)) ;;
    esac

    SUM_MS["$suite"]=$((SUM_MS["$suite"] + duration_ms))
    if [ "${MIN_MS[$suite]}" -lt 0 ] || [ "$duration_ms" -lt "${MIN_MS[$suite]}" ]; then
      MIN_MS["$suite"]="$duration_ms"
    fi
    if [ "$duration_ms" -gt "${MAX_MS[$suite]}" ]; then
      MAX_MS["$suite"]="$duration_ms"
    fi

    LOG_PATHS["$suite"]+="$log_file;"
    STATUS_TRACE["$suite"]+="$status,"

    if grep -Eqi "timeout|timed out|deadline" "$log_file"; then
      HAS_TIMEOUT["$suite"]=true
    fi
    if grep -Eqi "panicked at|thread '.*' panicked" "$log_file"; then
      HAS_PANIC["$suite"]=true
    fi
    if grep -Eqi "divergence|replay divergence|trace divergence" "$log_file"; then
      HAS_DIVERGENCE["$suite"]=true
    fi

    echo "  run $i/$ITERATIONS: $status (${duration_ms}ms)"

    if [ "$VERBOSE" = true ] && [ "$status" != "pass" ]; then
      echo "  --- tail: $log_file ---"
      tail -20 "$log_file" || true
      echo "  --- end tail ---"
    fi

    jq -n \
      --arg schema_version "sem-verification-log-v1" \
      --arg entry_id "svl-${RUN_ID}-${suite}-$(printf "%03d" "$i")" \
      --arg run_id "$RUN_ID" \
      --arg phase "check" \
      --arg rule_id "inv.determinism.replayable" \
      --argjson rule_number 46 \
      --arg domain "determinism" \
      --arg evidence_class "CI" \
      --arg scenario_id "$scenario_id" \
      --arg verdict "$status" \
      --arg repro_command "$cmd" \
      --arg witness_id "${SUITE_WITNESS[$suite]}" \
      --argjson seq "$i" \
      --argjson timestamp_ns "$end_ns" \
      --argjson seed "$SEED" \
      --arg artifact_path "$log_file" \
      --arg verdict_reason "$([ "$status" = "pass" ] && echo "" || echo "deterministic replay variance signal")" \
      '{
        schema_version: $schema_version,
        entry_id: $entry_id,
        run_id: $run_id,
        seq: $seq,
        timestamp_ns: $timestamp_ns,
        phase: $phase,
        rule_id: $rule_id,
        rule_number: $rule_number,
        domain: $domain,
        evidence_class: $evidence_class,
        scenario_id: $scenario_id,
        verdict: $verdict,
        seed: $seed,
        repro_command: $repro_command,
        witness_id: $witness_id,
        artifact_path: $artifact_path
      } + (if $verdict == "pass" then {} else {verdict_reason: $verdict_reason} end)' >> "$EVENTS_FILE"
  done

  min_ms="${MIN_MS[$suite]}"
  max_ms="${MAX_MS[$suite]}"
  mean_ms=$((SUM_MS["$suite"] / ITERATIONS))
  spread_pct="$(awk -v min="$min_ms" -v max="$max_ms" 'BEGIN { if (min <= 0) { print "0.00" } else { printf "%.2f", ((max - min) * 100.0) / min } }')"
  DURATION_SPREAD_PCT["$suite"]="$spread_pct"

  unstable=false
  reasons=()

  if [ "${PASS_COUNT[$suite]}" -gt 0 ] && [ "${FAIL_COUNT[$suite]}" -gt 0 ]; then
    unstable=true
    reasons+=("status_variance")
  fi

  if awk -v spread="$spread_pct" -v threshold="$DURATION_THRESHOLD_PCT" 'BEGIN { exit !(spread > threshold) }'; then
    unstable=true
    reasons+=("duration_variance")
  fi

  if [ "${HAS_TIMEOUT[$suite]}" = true ]; then
    reasons+=("timeout_or_deadline_pressure")
  fi
  if [ "${HAS_PANIC[$suite]}" = true ]; then
    reasons+=("panic_path")
  fi
  if [ "${HAS_DIVERGENCE[$suite]}" = true ]; then
    reasons+=("trace_divergence")
  fi
  if [ "${FAIL_COUNT[$suite]}" -eq "$ITERATIONS" ]; then
    reasons+=("deterministic_failure")
  fi
  if [ "${#reasons[@]}" -eq 0 ]; then
    reasons+=("none")
  fi

  UNSTABLE["$suite"]="$unstable"
  UNSTABLE_REASONS["$suite"]="$(IFS=,; echo "${reasons[*]}")"

  if [ "$unstable" = true ]; then
    UNSTABLE_COUNT=$((UNSTABLE_COUNT + 1))
  fi

  echo "  summary: pass=${PASS_COUNT[$suite]} fail=${FAIL_COUNT[$suite]} skip=${SKIP_COUNT[$suite]} spread=${spread_pct}% unstable=${unstable}"
  echo ""
done

echo "=== variance summary ===" | tee "$SUMMARY_FILE"
echo "run_id: $RUN_ID" | tee -a "$SUMMARY_FILE"
echo "unstable_suites: $UNSTABLE_COUNT" | tee -a "$SUMMARY_FILE"
echo "suite_count: ${#SUITES[@]}" | tee -a "$SUMMARY_FILE"
echo "events_file: $EVENTS_FILE" | tee -a "$SUMMARY_FILE"
echo "" | tee -a "$SUMMARY_FILE"

suite_payloads=()
for suite in "${SUITES[@]}"; do
  IFS=';' read -r -a suite_logs_raw <<< "${LOG_PATHS[$suite]}"
  suite_logs=()
  for lp in "${suite_logs_raw[@]}"; do
    if [ -n "$lp" ]; then
      suite_logs+=("$lp")
    fi
  done

  suite_logs_json="$(printf '%s\n' "${suite_logs[@]}" | jq -R . | jq -s '.')"
  reasons_json="$(printf '%s\n' "${UNSTABLE_REASONS[$suite]}" | tr ',' '\n' | sed '/^$/d' | jq -R . | jq -s '.')"

  suite_json="$(jq -n \
    --arg suite "$suite" \
    --arg witness_id "${SUITE_WITNESS[$suite]}" \
    --arg scenario_id "${SUITE_SCENARIO[$suite]}" \
    --arg command "$cmd" \
    --arg replay_command "$cmd" \
    --arg status_trace "${STATUS_TRACE[$suite]}" \
    --argjson passes "${PASS_COUNT[$suite]}" \
    --argjson failures "${FAIL_COUNT[$suite]}" \
    --argjson skips "${SKIP_COUNT[$suite]}" \
    --arg unstable "${UNSTABLE[$suite]}" \
    --argjson min_ms "${MIN_MS[$suite]}" \
    --argjson max_ms "${MAX_MS[$suite]}" \
    --argjson mean_ms "$((SUM_MS[$suite] / ITERATIONS))" \
    --arg spread_pct "${DURATION_SPREAD_PCT[$suite]}" \
    --argjson logs "$suite_logs_json" \
    --argjson variance_sources "$reasons_json" \
    '{
      suite: $suite,
      witness_ids: [$witness_id],
      scenario_id: $scenario_id,
      iterations: ($passes + $failures + $skips),
      outcomes: {
        pass: $passes,
        fail: $failures,
        skip: $skips,
        status_trace: ($status_trace | split(",") | map(select(length > 0)))
      },
      unstable: ($unstable == "true"),
      likely_variance_sources: $variance_sources,
      duration_ms: {
        min: $min_ms,
        max: $max_ms,
        mean: $mean_ms,
        spread_pct: ($spread_pct | tonumber)
      },
      replay_command: $replay_command,
      command: $command,
      artifacts: {
        logs: $logs
      }
    }')"
  suite_payloads+=("$suite_json")
done

suites_json="$(printf '%s\n' "${suite_payloads[@]}" | jq -s '.')"
unstable_names_json="$(jq -n --argjson suites "$suites_json" '$suites | map(select(.unstable == true) | .suite)')"

recommendations_json="$(jq -n \
  --argjson unstable "$unstable_names_json" \
  'if ($unstable | length) == 0 then
      ["No instability detected; keep current deterministic replay cadence."]
    else
      [
        "Investigate unstable suites first using replay_command and per-run logs.",
        "Increase deterministic replay iteration count in CI for unstable suites.",
        "Correlate instability with SEM-10.5 CI signal-quality tuning."
      ]
    end')"

if [ "$JSON_OUTPUT" = true ]; then
  jq -n \
    --arg schema_version "sem-variance-dashboard-v1" \
    --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg run_id "$RUN_ID" \
    --argjson seed "$SEED" \
    --argjson iterations "$ITERATIONS" \
    --arg ci_mode "$CI_MODE" \
    --argjson suite_count "${#SUITES[@]}" \
    --argjson unstable_count "$UNSTABLE_COUNT" \
    --argjson suites "$suites_json" \
    --argjson unstable_suites "$unstable_names_json" \
    --argjson recommendations "$recommendations_json" \
    --arg events_file "$EVENTS_FILE" \
    --arg summary_file "$SUMMARY_FILE" \
    '{
      schema_version: $schema_version,
      generated_at: $generated_at,
      run_id: $run_id,
      seed: $seed,
      iterations: $iterations,
      ci_mode: ($ci_mode == "true"),
      suite_count: $suite_count,
      unstable_suite_count: $unstable_count,
      suites: $suites,
      unstable_suites: $unstable_suites,
      recommendations: $recommendations,
      artifacts: {
        variance_events_ndjson: $events_file,
        summary: $summary_file
      }
    }' > "$DASHBOARD_FILE"
fi

echo "dashboard: $DASHBOARD_FILE"

if [ "$CI_MODE" = true ]; then
  if [ "$RUN_FAILED" -ne 0 ] || [ "$UNSTABLE_COUNT" -gt 0 ]; then
    echo "CI verdict: FAIL (run_failed=$RUN_FAILED unstable_suites=$UNSTABLE_COUNT)"
    exit 1
  fi
fi

if [ "$RUN_FAILED" -ne 0 ] || [ "$UNSTABLE_COUNT" -gt 0 ]; then
  echo "verdict: FAIL (run_failed=$RUN_FAILED unstable_suites=$UNSTABLE_COUNT)"
  exit 1
fi

echo "verdict: PASS"
exit 0
