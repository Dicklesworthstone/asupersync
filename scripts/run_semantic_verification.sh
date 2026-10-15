#!/usr/bin/env bash
# Unified Semantic Verification Runner (SEM-12.9)
#
# Single entrypoint for all semantic verification suites.
# Orchestrates docs lint, runtime tests, golden fixtures, Lean proofs,
# and TLA+ model checks with consistent output and CI/local parity.
#
# Usage:
#   scripts/run_semantic_verification.sh [OPTIONS]
#
# Options:
#   --profile PROFILE   Run profile: smoke (fast), full (default), forensics (verbose)
#   --json              Write structured JSON report
#   --ci                CI mode: strict exit codes, artifact publishing
#   --verbose           Verbose output for all suites
#   --suite SUITE       Run only specified suite (docs, runtime, golden, lean, tla, logging)
#
# Exit codes:
#   0 - All suites passed
#   1 - One or more suites failed
#   2 - Configuration error
#
# Beads: asupersync-3cddg.12.9, asupersync-3cddg.12.14

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPORT_DIR="$PROJECT_ROOT/target/semantic-verification"
REPORT_FILE="$REPORT_DIR/verification_report.json"
PROFILE="full"
JSON_OUTPUT=false
CI_MODE=false
VERBOSE=false
SUITE_FILTER=""
SEM_MATRIX_FILE="$PROJECT_ROOT/docs/semantic_verification_matrix.md"
SEM_LOG_SCHEMA_FILE="$PROJECT_ROOT/docs/semantic_verification_log_schema.md"
RCH_BIN="${RCH_BIN:-rch}"
RCH_CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${TMPDIR:-/tmp}/rch_target_semantic_verification}"

# SEM-12.14 quality gate thresholds (coverage percentages).
GLOBAL_UT_MIN_PCT=100
GLOBAL_PT_MIN_PCT=40
GLOBAL_E2E_MIN_PCT=60

declare -A DOMAIN_UT_MIN_PCT=(
  [cancel]=100
  [obligation]=100
  [region]=100
  [outcome]=100
  [ownership]=100
  [combinator]=100
  [capability]=0
  [determinism]=100
)
declare -A DOMAIN_PT_MIN_PCT=(
  [cancel]=25
  [obligation]=20
  [region]=15
  [outcome]=25
  [ownership]=0
  [combinator]=40
  [capability]=0
  [determinism]=0
)
declare -A DOMAIN_E2E_MIN_PCT=(
  [cancel]=25
  [obligation]=20
  [region]=15
  [outcome]=0
  [ownership]=0
  [combinator]=40
  [capability]=0
  [determinism]=100
)
COVERAGE_GATE_DOMAINS=(cancel obligation region outcome ownership combinator capability determinism)

COVERAGE_GATE_ENFORCED=false
COVERAGE_GATE_STATUS="skipped"
declare -a COVERAGE_GATE_FAILURES=()
declare -A COVERAGE_GATE_DOMAIN_TOTAL=()
declare -A COVERAGE_GATE_DOMAIN_UT=()
declare -A COVERAGE_GATE_DOMAIN_PT=()
declare -A COVERAGE_GATE_DOMAIN_E2E=()
COVERAGE_GATE_GLOBAL_UT=0
COVERAGE_GATE_GLOBAL_PT=0
COVERAGE_GATE_GLOBAL_E2E=0

COVERAGE_GATE_GLOBAL_THRESHOLDS_JSON="{}"
COVERAGE_GATE_GLOBAL_OBSERVED_JSON="{}"
COVERAGE_GATE_DOMAIN_THRESHOLDS_JSON="{}"
COVERAGE_GATE_DOMAIN_OBSERVED_JSON="{}"
COVERAGE_GATE_FAILURES_JSON="[]"
PROFILE_RUNTIME_BUDGET_S=900
PROFILE_REQUIRED_ARTIFACTS=""
PROFILE_REQUIRED_LOG_OUTPUTS=""
PROFILE_INCLUDED_COMPONENTS=""
PROFILE_SKIPPED_COMPONENTS=""
PROFILE_BUDGET_STATUS="within_budget"
PROFILE_SUITE_INCLUSION_JSON="[]"
PROFILE_SKIPPED_JSON="[]"
PROFILE_REQUIRED_ARTIFACTS_JSON="[]"
PROFILE_REQUIRED_LOG_OUTPUTS_JSON="[]"

# Parse arguments
while [ $# -gt 0 ]; do
  case "$1" in
    --profile) PROFILE="$2"; shift 2 ;;
    --json) JSON_OUTPUT=true; shift ;;
    --ci) CI_MODE=true; JSON_OUTPUT=true; shift ;;
    --verbose) VERBOSE=true; shift ;;
    --suite) SUITE_FILTER="$2"; shift 2 ;;
    -h|--help)
      head -28 "$0" | tail -25
      exit 0
      ;;
    *) echo "Unknown argument: $1"; exit 2 ;;
  esac
done

mkdir -p "$REPORT_DIR"

# ─── Suite definitions ────────────────────────────────────────────

# Each suite: required?
declare -A SUITE_REQUIRED

ALL_PROFILE_COMPONENTS="docs golden lean_validation tla_validation logging_schema lean_build tla_check coverage_gate"

# Required suites must pass; optional suites are reported but don't fail the run
SUITE_REQUIRED[docs]=true
SUITE_REQUIRED[golden]=true
SUITE_REQUIRED[lean_validation]=true
SUITE_REQUIRED[tla_validation]=true
SUITE_REQUIRED[logging_schema]=true
SUITE_REQUIRED[lean_build]=false    # Requires Lean toolchain
SUITE_REQUIRED[tla_check]=false     # Requires TLC

run_cargo() {
  "$RCH_BIN" exec -- env CARGO_TARGET_DIR="$RCH_CARGO_TARGET_DIR" cargo "$@"
}

run_suite_command() {
  local suite="$1"

  case "$suite" in
    docs)
      run_cargo test --test semantic_docs_lint --test semantic_docs_rule_mapping_lint
      ;;
    golden)
      run_cargo test --test semantic_golden_fixture_validation
      ;;
    lean_validation)
      run_cargo test --test semantic_lean_regression
      ;;
    tla_validation)
      run_cargo test --test semantic_tla_scenarios
      ;;
    logging_schema)
      run_cargo test --test semantic_log_schema_validation --test semantic_witness_replay_e2e
      ;;
    lean_build)
      scripts/run_lean_regression.sh --json
      ;;
    tla_check)
      scripts/run_tla_scenarios.sh --json
      ;;
    *)
      echo "ERROR: Unknown suite command: $suite" >&2
      return 2
      ;;
  esac
}

# Profile-based suite selection
case "$PROFILE" in
  smoke)
    SUITES="docs golden"
    PROFILE_RUNTIME_BUDGET_S=180
    PROFILE_REQUIRED_ARTIFACTS="verification_report.json docs_output.txt golden_output.txt"
    PROFILE_REQUIRED_LOG_OUTPUTS="profile_selected suite_plan skipped_components suite_results summary"
    ;;
  full)
    SUITES="docs golden lean_validation tla_validation logging_schema lean_build tla_check"
    PROFILE_RUNTIME_BUDGET_S=1200
    PROFILE_REQUIRED_ARTIFACTS="verification_report.json docs_output.txt golden_output.txt lean_validation_output.txt tla_validation_output.txt logging_schema_output.txt lean_build_output.txt tla_check_output.txt"
    PROFILE_REQUIRED_LOG_OUTPUTS="profile_selected suite_plan skipped_components suite_results coverage_gate summary"
    ;;
  forensics)
    SUITES="docs golden lean_validation tla_validation logging_schema lean_build tla_check"
    VERBOSE=true
    PROFILE_RUNTIME_BUDGET_S=1800
    PROFILE_REQUIRED_ARTIFACTS="verification_report.json docs_output.txt golden_output.txt lean_validation_output.txt tla_validation_output.txt logging_schema_output.txt lean_build_output.txt tla_check_output.txt coverage_gate_diagnostics"
    PROFILE_REQUIRED_LOG_OUTPUTS="profile_selected suite_plan skipped_components suite_results coverage_gate verbose_failure_tail summary"
    ;;
  *)
    echo "ERROR: Unknown profile '$PROFILE'. Use: smoke, full, forensics"
    exit 2
    ;;
esac

# Apply suite filter if specified
if [ -n "$SUITE_FILTER" ]; then
  case "$SUITE_FILTER" in
    docs) SUITES="docs" ;;
    runtime) SUITES="lean_validation tla_validation" ;;
    golden) SUITES="golden" ;;
    lean) SUITES="lean_validation lean_build" ;;
    tla) SUITES="tla_validation tla_check" ;;
    logging) SUITES="logging_schema" ;;
    *) echo "ERROR: Unknown suite '$SUITE_FILTER'. Use: docs, runtime, golden, lean, tla, logging"; exit 2 ;;
  esac
fi

if [ "$PROFILE" != "smoke" ] && [ -z "$SUITE_FILTER" ]; then
  PROFILE_INCLUDED_COMPONENTS="$SUITES coverage_gate"
else
  PROFILE_INCLUDED_COMPONENTS="$SUITES"
fi

for component in $ALL_PROFILE_COMPONENTS; do
  case " $PROFILE_INCLUDED_COMPONENTS " in
    *" $component "*) ;;
    *)
      PROFILE_SKIPPED_COMPONENTS="$PROFILE_SKIPPED_COMPONENTS $component"
      ;;
  esac
done
PROFILE_SKIPPED_COMPONENTS="$(echo "$PROFILE_SKIPPED_COMPONENTS" | xargs || true)"

# ─── Run suites ──────────────────────────────────────────────────

log() {
  echo "[semantic-verify] $*"
}

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

is_rch_local_fallback() {
  grep -Eq '^\[RCH\] local \(|falling back to local'
}

build_space_list_json() {
  local list="$1"
  local json="["
  local first=true
  local item
  local escaped
  for item in $list; do
    escaped=$(json_escape "$item")
    if [ "$first" = false ]; then
      json+=","
    fi
    json+="\"$escaped\""
    first=false
  done
  json+="]"
  printf '%s' "$json"
}

extract_global_evidence_pct() {
  local evidence="$1"
  awk -F'|' -v evidence="$evidence" '
    function trim(s) { gsub(/^[ \t]+|[ \t]+$/, "", s); return s }
    $0 ~ "^\\|[[:space:]]*" evidence "[[:space:]]*\\|" {
      value = trim($5)
      gsub(/[^0-9]/, "", value)
      if (value == "") value = "0"
      print value
      exit
    }
  ' "$SEM_MATRIX_FILE"
}

build_domain_coverage_snapshot() {
  awk '
    function trim(s) { gsub(/^[ \t]+|[ \t]+$/, "", s); return s }
    BEGIN { domain = "" }
    match($0, /^### 4\.[0-9]+ ([A-Za-z]+) Domain/, m) {
      domain = tolower(m[1])
      next
    }
    domain != "" && $0 ~ /^\|[[:space:]]*[0-9]+[[:space:]]*\|/ {
      split($0, parts, "|")
      ut = trim(parts[5])
      pt = trim(parts[6])
      e2e = trim(parts[8])
      total[domain]++
      if (ut == "Y") ut_yes[domain]++
      if (pt == "Y") pt_yes[domain]++
      if (e2e == "Y") e2e_yes[domain]++
    }
    END {
      for (d in total) {
        ut_pct = (total[d] > 0) ? int((ut_yes[d] * 100) / total[d]) : 0
        pt_pct = (total[d] > 0) ? int((pt_yes[d] * 100) / total[d]) : 0
        e2e_pct = (total[d] > 0) ? int((e2e_yes[d] * 100) / total[d]) : 0
        printf "%s|%d|%d|%d|%d\n", d, total[d], ut_pct, pt_pct, e2e_pct
      }
    }
  ' "$SEM_MATRIX_FILE"
}

build_domain_thresholds_json() {
  local json="{"
  local first=true
  local domain
  for domain in "${COVERAGE_GATE_DOMAINS[@]}"; do
    if [ "$first" = false ]; then
      json+=","
    fi
    json+="\"$domain\":{\"UT\":${DOMAIN_UT_MIN_PCT[$domain]},\"PT\":${DOMAIN_PT_MIN_PCT[$domain]},\"E2E\":${DOMAIN_E2E_MIN_PCT[$domain]}}"
    first=false
  done
  json+="}"
  printf '%s' "$json"
}

build_domain_observed_json() {
  local json="{"
  local first=true
  local domain
  for domain in "${COVERAGE_GATE_DOMAINS[@]}"; do
    if [ "$first" = false ]; then
      json+=","
    fi
    json+="\"$domain\":{\"total_rules\":${COVERAGE_GATE_DOMAIN_TOTAL[$domain]:-0},\"UT\":${COVERAGE_GATE_DOMAIN_UT[$domain]:-0},\"PT\":${COVERAGE_GATE_DOMAIN_PT[$domain]:-0},\"E2E\":${COVERAGE_GATE_DOMAIN_E2E[$domain]:-0}}"
    first=false
  done
  json+="}"
  printf '%s' "$json"
}

build_failure_json() {
  local json="["
  local first=true
  local failure escaped
  for failure in "${COVERAGE_GATE_FAILURES[@]}"; do
    escaped=$(json_escape "$failure")
    if [ "$first" = false ]; then
      json+=","
    fi
    json+="\"$escaped\""
    first=false
  done
  json+="]"
  printf '%s' "$json"
}

add_gate_failure() {
  COVERAGE_GATE_FAILURES+=("$1")
  log "  coverage-gate: $1"
}

TOTAL=0
PASSED=0
FAILED=0
SKIPPED=0
RESULTS=()
declare -A SUITE_STATUS

RUN_START=$(date +%s)

log "Profile selected: $PROFILE (runtime budget ${PROFILE_RUNTIME_BUDGET_S}s)"
log "Suite plan: $PROFILE_INCLUDED_COMPONENTS"
if [ -n "$PROFILE_SKIPPED_COMPONENTS" ]; then
  log "Skipped components: $PROFILE_SKIPPED_COMPONENTS"
else
  log "Skipped components: none"
fi
if [ -n "$SUITE_FILTER" ]; then
  log "Suite filter active: $SUITE_FILTER"
fi

for suite in $SUITES; do
  ((TOTAL++)) || true
  required="${SUITE_REQUIRED[$suite]}"

  log "Running suite: $suite"
  SUITE_START=$(date +%s)

  suite_output=""
  suite_exit=0
  suite_local_fallback=false
  suite_output=$(cd "$PROJECT_ROOT" && run_suite_command "$suite" 2>&1) || suite_exit=$?
  if printf '%s\n' "$suite_output" | is_rch_local_fallback; then
    suite_local_fallback=true
    suite_exit=86
    suite_output="${suite_output}"$'\n'"FATAL: rch local fallback detected; refusing local cargo execution"
  fi

  SUITE_END=$(date +%s)
  SUITE_DURATION=$((SUITE_END - SUITE_START))

  if [ "$suite_exit" -eq 0 ]; then
    status="passed"
    ((PASSED++)) || true
    log "  $suite: PASSED (${SUITE_DURATION}s)"
  else
    # Check if it was a graceful skip
    if [ "$suite_local_fallback" = true ]; then
      status="failed"
      ((FAILED++)) || true
      log "  $suite: FAILED (${SUITE_DURATION}s, rch local fallback)"
      if [ "$VERBOSE" = true ]; then
        echo "$suite_output" | tail -20
      fi
    elif echo "$suite_output" | grep -q "SKIP:"; then
      status="skipped"
      ((SKIPPED++)) || true
      log "  $suite: SKIPPED (${SUITE_DURATION}s)"
    else
      status="failed"
      ((FAILED++)) || true
      log "  $suite: FAILED (${SUITE_DURATION}s)"
      if [ "$VERBOSE" = true ]; then
        echo "$suite_output" | tail -20
      fi
    fi
  fi

  RESULTS+=("$suite|$status|$SUITE_DURATION|$required")
  SUITE_STATUS[$suite]="$status"

  # Save suite output
  echo "$suite_output" > "$REPORT_DIR/${suite}_output.txt"
done

if [ "$PROFILE" != "smoke" ] && [ -z "$SUITE_FILTER" ]; then
  COVERAGE_GATE_ENFORCED=true
  log "Evaluating SEM-12.14 coverage/logging gate..."

  if [ ! -f "$SEM_MATRIX_FILE" ]; then
    add_gate_failure "missing matrix file: $SEM_MATRIX_FILE"
  else
    COVERAGE_GATE_GLOBAL_UT=$(extract_global_evidence_pct "UT")
    COVERAGE_GATE_GLOBAL_PT=$(extract_global_evidence_pct "PT")
    COVERAGE_GATE_GLOBAL_E2E=$(extract_global_evidence_pct "E2E")

    if [ -z "${COVERAGE_GATE_GLOBAL_UT}" ] || [ -z "${COVERAGE_GATE_GLOBAL_PT}" ] || [ -z "${COVERAGE_GATE_GLOBAL_E2E}" ]; then
      add_gate_failure "unable to parse UT/PT/E2E coverage percentages from semantic_verification_matrix.md"
    else
      if [ "$COVERAGE_GATE_GLOBAL_UT" -lt "$GLOBAL_UT_MIN_PCT" ]; then
        add_gate_failure "global UT coverage ${COVERAGE_GATE_GLOBAL_UT}% is below threshold ${GLOBAL_UT_MIN_PCT}%"
      fi
      if [ "$COVERAGE_GATE_GLOBAL_PT" -lt "$GLOBAL_PT_MIN_PCT" ]; then
        add_gate_failure "global PT coverage ${COVERAGE_GATE_GLOBAL_PT}% is below threshold ${GLOBAL_PT_MIN_PCT}%"
      fi
      if [ "$COVERAGE_GATE_GLOBAL_E2E" -lt "$GLOBAL_E2E_MIN_PCT" ]; then
        add_gate_failure "global E2E coverage ${COVERAGE_GATE_GLOBAL_E2E}% is below threshold ${GLOBAL_E2E_MIN_PCT}%"
      fi
    fi

    while IFS='|' read -r domain total ut_pct pt_pct e2e_pct; do
      [ -n "$domain" ] || continue
      COVERAGE_GATE_DOMAIN_TOTAL[$domain]="$total"
      COVERAGE_GATE_DOMAIN_UT[$domain]="$ut_pct"
      COVERAGE_GATE_DOMAIN_PT[$domain]="$pt_pct"
      COVERAGE_GATE_DOMAIN_E2E[$domain]="$e2e_pct"
    done < <(build_domain_coverage_snapshot)

    for domain in "${COVERAGE_GATE_DOMAINS[@]}"; do
      if [ -z "${COVERAGE_GATE_DOMAIN_TOTAL[$domain]:-}" ]; then
        add_gate_failure "domain coverage missing from matrix: $domain"
        continue
      fi
      if [ "${COVERAGE_GATE_DOMAIN_UT[$domain]}" -lt "${DOMAIN_UT_MIN_PCT[$domain]}" ]; then
        add_gate_failure "domain '$domain' UT coverage ${COVERAGE_GATE_DOMAIN_UT[$domain]}% is below threshold ${DOMAIN_UT_MIN_PCT[$domain]}%"
      fi
      if [ "${COVERAGE_GATE_DOMAIN_PT[$domain]}" -lt "${DOMAIN_PT_MIN_PCT[$domain]}" ]; then
        add_gate_failure "domain '$domain' PT coverage ${COVERAGE_GATE_DOMAIN_PT[$domain]}% is below threshold ${DOMAIN_PT_MIN_PCT[$domain]}%"
      fi
      if [ "${COVERAGE_GATE_DOMAIN_E2E[$domain]}" -lt "${DOMAIN_E2E_MIN_PCT[$domain]}" ]; then
        add_gate_failure "domain '$domain' E2E coverage ${COVERAGE_GATE_DOMAIN_E2E[$domain]}% is below threshold ${DOMAIN_E2E_MIN_PCT[$domain]}%"
      fi
    done
  fi

  if [ "${SUITE_STATUS[logging_schema]:-missing}" != "passed" ]; then
    add_gate_failure "logging schema suite must pass (semantic_log_schema_validation + semantic_witness_replay_e2e)"
  fi

  if [ ! -f "$SEM_LOG_SCHEMA_FILE" ]; then
    add_gate_failure "missing log schema file: $SEM_LOG_SCHEMA_FILE"
  else
    for required_field in schema_version entry_id run_id seq rule_id evidence_class verdict seed repro_command parent_run_id thread_id artifact_path artifact_hash; do
      if ! grep -Fq "\`$required_field\`" "$SEM_LOG_SCHEMA_FILE"; then
        add_gate_failure "log schema documentation missing required field entry: $required_field"
      fi
    done
    if ! grep -Fq '"summary.json"' "$SEM_LOG_SCHEMA_FILE" || ! grep -Fq '"entries.ndjson"' "$SEM_LOG_SCHEMA_FILE"; then
      add_gate_failure "log schema documentation missing summary/artifact linkage requirements (summary.json + entries.ndjson)"
    fi
    if ! grep -Fq "Correlation IDs connect evidence across tools and runs." "$SEM_LOG_SCHEMA_FILE"; then
      add_gate_failure "log schema documentation missing correlation-link integrity requirement"
    fi
  fi

  if [ "${#COVERAGE_GATE_FAILURES[@]}" -eq 0 ]; then
    COVERAGE_GATE_STATUS="passed"
    ((PASSED++)) || true
  else
    COVERAGE_GATE_STATUS="failed"
    ((FAILED++)) || true
  fi
  ((TOTAL++)) || true
  RESULTS+=("coverage_gate|$COVERAGE_GATE_STATUS|0|true")
  SUITE_STATUS[coverage_gate]="$COVERAGE_GATE_STATUS"
else
  COVERAGE_GATE_STATUS="skipped"
  ((SKIPPED++)) || true
  ((TOTAL++)) || true
  RESULTS+=("coverage_gate|skipped|0|false")
  SUITE_STATUS[coverage_gate]="skipped"
fi

COVERAGE_GATE_GLOBAL_THRESHOLDS_JSON="{\"UT\":$GLOBAL_UT_MIN_PCT,\"PT\":$GLOBAL_PT_MIN_PCT,\"E2E\":$GLOBAL_E2E_MIN_PCT}"
COVERAGE_GATE_GLOBAL_OBSERVED_JSON="{\"UT\":$COVERAGE_GATE_GLOBAL_UT,\"PT\":$COVERAGE_GATE_GLOBAL_PT,\"E2E\":$COVERAGE_GATE_GLOBAL_E2E}"
COVERAGE_GATE_DOMAIN_THRESHOLDS_JSON="$(build_domain_thresholds_json)"
COVERAGE_GATE_DOMAIN_OBSERVED_JSON="$(build_domain_observed_json)"
COVERAGE_GATE_FAILURES_JSON="$(build_failure_json)"

RUN_END=$(date +%s)
TOTAL_DURATION=$((RUN_END - RUN_START))
if [ "$TOTAL_DURATION" -gt "$PROFILE_RUNTIME_BUDGET_S" ]; then
  PROFILE_BUDGET_STATUS="exceeded"
  log "Profile budget exceeded: duration=${TOTAL_DURATION}s budget=${PROFILE_RUNTIME_BUDGET_S}s"
fi
PROFILE_SUITE_INCLUSION_JSON="$(build_space_list_json "$PROFILE_INCLUDED_COMPONENTS")"
PROFILE_SKIPPED_JSON="$(build_space_list_json "$PROFILE_SKIPPED_COMPONENTS")"
PROFILE_REQUIRED_ARTIFACTS_JSON="$(build_space_list_json "$PROFILE_REQUIRED_ARTIFACTS")"
PROFILE_REQUIRED_LOG_OUTPUTS_JSON="$(build_space_list_json "$PROFILE_REQUIRED_LOG_OUTPUTS")"

# ─── Summary ─────────────────────────────────────────────────────

echo ""
echo "══════════════════════════════════════════════════"
echo " Semantic Verification Summary ($PROFILE profile)"
echo "══════════════════════════════════════════════════"
echo ""
printf "  %-20s %s\n" "Total suites:" "$TOTAL"
printf "  %-20s %s\n" "Passed:" "$PASSED"
printf "  %-20s %s\n" "Failed:" "$FAILED"
printf "  %-20s %s\n" "Skipped:" "$SKIPPED"
printf "  %-20s %s\n" "Duration:" "${TOTAL_DURATION}s"
echo ""
echo "  Suite Results:"
for result in "${RESULTS[@]}"; do
  IFS='|' read -r name rstatus dur req <<< "$result"
  case "$rstatus" in
    passed)  marker="[PASS]" ;;
    failed)  marker="[FAIL]" ;;
    skipped) marker="[SKIP]" ;;
    *)       marker="[????]" ;;
  esac
  printf "    %-20s %s  (%ss)\n" "$name" "$marker" "$dur"
done
echo ""

# ─── JSON report ─────────────────────────────────────────────────

if [ "$JSON_OUTPUT" = true ]; then
  RESULTS_JSON="["
  FIRST=true
  for result in "${RESULTS[@]}"; do
    IFS='|' read -r name rstatus dur req <<< "$result"
    if [ "$FIRST" = false ]; then RESULTS_JSON+=","; fi
    RESULTS_JSON+="{\"suite\":\"$name\",\"status\":\"$rstatus\",\"duration_s\":$dur,\"required\":$req}"
    FIRST=false
  done
  RESULTS_JSON+="]"

  cat > "$REPORT_FILE" <<EOF
{
  "schema": "semantic-verification-report-v1",
  "profile": "$PROFILE",
  "ci_mode": $CI_MODE,
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "total_duration_s": $TOTAL_DURATION,
  "suites_total": $TOTAL,
  "suites_passed": $PASSED,
  "suites_failed": $FAILED,
  "suites_skipped": $SKIPPED,
  "overall_status": "$([ "$FAILED" -eq 0 ] && echo "passed" || echo "failed")",
  "results": $RESULTS_JSON,
  "quality_gates": {
    "semantic_coverage_logging_gate": {
      "enforced": $COVERAGE_GATE_ENFORCED,
      "status": "$COVERAGE_GATE_STATUS",
      "global_thresholds": $COVERAGE_GATE_GLOBAL_THRESHOLDS_JSON,
      "global_observed": $COVERAGE_GATE_GLOBAL_OBSERVED_JSON,
      "domain_thresholds": $COVERAGE_GATE_DOMAIN_THRESHOLDS_JSON,
      "domain_observed": $COVERAGE_GATE_DOMAIN_OBSERVED_JSON,
      "failures": $COVERAGE_GATE_FAILURES_JSON
    }
  },
  "profile_contract": {
    "runtime_budget_s": $PROFILE_RUNTIME_BUDGET_S,
    "budget_status": "$PROFILE_BUDGET_STATUS",
    "suite_inclusion": $PROFILE_SUITE_INCLUSION_JSON,
    "suite_skipped": $PROFILE_SKIPPED_JSON,
    "required_artifacts": $PROFILE_REQUIRED_ARTIFACTS_JSON,
    "required_log_outputs": $PROFILE_REQUIRED_LOG_OUTPUTS_JSON
  },
  "report_dir": "$REPORT_DIR"
}
EOF
  log "JSON report: $REPORT_FILE"
fi

# ─── Exit code ───────────────────────────────────────────────────

# In CI mode, only required suite failures cause non-zero exit
if [ "$CI_MODE" = true ]; then
  REQUIRED_FAILURES=0
  for result in "${RESULTS[@]}"; do
    IFS='|' read -r name rstatus dur req <<< "$result"
    if [ "$rstatus" = "failed" ] && [ "$req" = "true" ]; then
      ((REQUIRED_FAILURES++)) || true
    fi
  done
  if [ "$REQUIRED_FAILURES" -gt 0 ]; then
    log "CI FAILED: $REQUIRED_FAILURES required suite(s) failed"
    exit 1
  fi
  exit 0
fi

# In local mode, any failure is an error
if [ "$FAILED" -gt 0 ]; then
  exit 1
fi
exit 0
